"""Dedicated publisher integration using local conditional stores, never AWS."""
from copy import deepcopy
from types import SimpleNamespace
from unittest import TestCase, mock
import publisher_lambda as publisher
import test_content_hub_v2_finalization as fixtures
from content_hub_v2_editor_store import METADATA_TABLE, PARTITION_PREFIX
from content_hub_v2_finalization import OPERATION_PK
from content_hub_v2_projection_store import PARTITION as PREPARATION_PK
from content_hub_v2_authorization import THN_CURRENT_USER_SCOPE
from content_hub_v2_actor_fence import USER_TABLE, SESSION_TABLE
from content_hub_v2_preparation import _sha, _bytes


class PublisherTests(TestCase):
    def setUp(self):
        self.assertTrue(callable(getattr(publisher, 'handle_publication', None)),
                        'dedicated publisher must connect to the atomic store')
        self.f = fixtures.FinalizationTests(); self.f.setUp(); self.f.prepare()
        import service_binding_registry_v2 as registry
        definition={k:self.f.registry[k] for k in registry.DEFINITION_FIELDS}
        definition['resourceBindings']={k:v.replace('123456789012','000000000000') for k,v in definition['resourceBindings'].items()}
        self.f.registry=registry.build_registry_record(definition,trusted_resource_scope={
            'partition':'aws','accountId':'000000000000','region':'us-east-1'})
        from service_binding_registry_consumer_v2 import APPROVED_TABLE_NAME
        self.f.ddb.seed(APPROVED_TABLE_NAME,self.f.registry)
        self.context = SimpleNamespace(invoked_function_arn='arn:aws:lambda:us-east-1:000000000000:function:zoolanding-content-hub-test-ThnV2Publisher:test')
        self.config = {
            'CONTENT_HUB_ENVIRONMENT':'test','CONTENT_HUB_DOMAIN':'thehairnarrative.com',
            'CONTENT_HUB_ID':'thehairnarrative-com-journal',
            'THN_CONTENT_HUB_METADATA_TABLE_NAME':METADATA_TABLE,
            'THN_CONTENT_HUB_PRIVATE_BUCKET_NAME':self.f.private_bucket,
            'CONTENT_HUB_METADATA_TABLE_NAME':self.f.public_table,
            'CONTENT_HUB_PACKAGES_BUCKET_NAME':self.f.delivery_bucket,
            'THN_CONTENT_HUB_DESCRIPTOR_VERSION_ID':self.f.registry['descriptorVersionId'],
            'THN_CONTENT_HUB_DESCRIPTOR_SHA256':self.f.registry['descriptorSha256'],
            'THN_CONTENT_HUB_AUTH_POLICY_VERSION':self.f.registry['authPolicyVersion'],
        }
        self.event = {**THN_CURRENT_USER_SCOPE,'schemaVersion':1,'source':'thn-authoring-v2',
            'operation':'publish','articleId':'a1','locale':'en','revisionId':'r1','expectedToken':'edit-r1',
            'operationId':'1'*32,'actorSubject':self.f.auth.subject,'actorPurpose':'client-owner',
            'sessionVersion':self.f.auth.session_version,'sessionIdHash':'a'*64,
            'writerMode':'client-owner','writerEpoch':7,'issuedAtEpoch':self.f.now}

    def run_event(self, event=None, config=None, context=None):
        runtime = publisher.PublicationRuntime(context or self.context, config or self.config,
            dynamodb=self.f.ddb, s3=self.f.s3, clock=lambda:self.f.now)
        return publisher.handle_publication(event or self.event, runtime=runtime)

    def test_prepared_publish_returns_only_safe_result_and_replays(self):
        first=self.run_event(); self.assertTrue(first['ok'])
        self.assertEqual(set(first['data']),{'articleId','locale','state','concurrencyToken'})
        self.assertEqual(first['data']['state'],'published')
        self.assertEqual(self.run_event(),first)
        self.assertIn('publishedRevisionId',self.f.article()['locales']['en'])

    def test_publish_prepares_private_sources_when_no_preparation_exists(self):
        prep='prep-'+_sha(_bytes(['a1','en','r1']))
        self.f.ddb.items.pop(self.f.ddb.identity(METADATA_TABLE,{'pk':PREPARATION_PK,'sk':'PREPARATION#'+prep}))
        self.f.s3.objects={k:v for k,v in self.f.s3.objects.items() if k[0]!=self.f.delivery_bucket}
        asset=self.f.ddb.row(METADATA_TABLE,{'pk':PARTITION_PREFIX+'ASSETS#a1#en','sk':'ASSET#m1'})
        for variant in asset['variants']:
            self.f.s3.objects[self.f.store.source_bucket,variant['key']]={'VersionId':variant['versionId'],
                'ContentType':variant['contentType'],'body':('synthetic-image-m1'+variant['variantId']).encode()}
        self.assertTrue(self.run_event()['ok'])
        self.assertEqual(len([k for k in self.f.s3.objects if k[0]==self.f.delivery_bucket]),5)

    def test_internal_envelope_rejects_browser_fields_and_unknown_scope_before_io(self):
        for change in ({'body':'html'},{'source':'browser'},{'domain':'other.example'},
                       {'writerEpoch':True},{'issuedAtEpoch':self.f.now-121},{'sessionIdHash':'raw-cookie'}):
            with self.subTest(change=change):
                before=len(self.f.ddb.calls)
                result=self.run_event({**self.event,**change})
                self.assertFalse(result['ok']); self.assertEqual(len(self.f.ddb.calls),before)

    def test_changed_user_purpose_version_and_disabled_user_cannot_publish(self):
        key={'pk':'CURRENT_USER#test#thn-journal-test-v2','sk':'SUBJECT#'+self.f.auth.subject}
        original=deepcopy(self.f.ddb.row(USER_TABLE,key))
        for change in ({'accountPurpose':'qa'},{'sessionVersion':2},{'enabled':False}):
            self.f.ddb.seed(USER_TABLE,{**original,**change})
            self.assertFalse(self.run_event()['ok'])
            self.assertNotIn('publishedRevisionId',self.f.article()['locales']['en'])
            self.assertFalse(self.f.s3.calls)

    def test_registry_epoch_and_writer_mode_are_reloaded(self):
        for field,value in (('writerEpoch',8),('writerMode','disabled')):
            with self.subTest(field=field):
                event={**self.event,field:value}
                self.assertFalse(self.run_event(event)['ok'])
                self.assertNotIn('publishedRevisionId',self.f.article()['locales']['en'])

    def test_session_is_only_checked_atomically_never_read(self):
        key={'sessionIdHash':'a'*64}
        self.f.ddb.seed(SESSION_TABLE,{**self.f.ddb.row(SESSION_TABLE,key),'revokedAt':self.f.now})
        self.assertFalse(self.run_event()['ok'])
        self.assertNotIn('publishedRevisionId',self.f.article()['locales']['en'])

    def test_unpublish_preserves_private_work_and_reservation(self):
        result=self.run_event()['data']
        event={**self.event,'operation':'unpublish','revisionId':'','expectedToken':result['concurrencyToken'],'operationId':'2'*32}
        self.assertEqual(self.run_event(event)['data']['state'],'unpublished')
        self.assertEqual(self.f.article()['locales']['en']['workingRevisionId'],'r1')
        self.assertEqual(self.run_event(event)['data']['state'],'unpublished')

    def test_wrong_function_alias_or_private_binding_fails_before_clients(self):
        with mock.patch('boto3.client') as client:
            for context in (SimpleNamespace(invoked_function_arn=self.context.invoked_function_arn[:-5]),
                            SimpleNamespace(invoked_function_arn=self.context.invoked_function_arn.replace(':test',':prod'))):
                with self.assertRaises(publisher.HandlerNotActiveError):
                    publisher.PublicationRuntime(context,self.config)
            with self.assertRaises(publisher.HandlerNotActiveError):
                publisher.PublicationRuntime(self.context,{**self.config,'THN_CONTENT_HUB_METADATA_TABLE_NAME':'other'})
            client.assert_not_called()

    def test_unexpected_lambda_event_fails_without_aws_client(self):
        with mock.patch('boto3.client') as client, self.assertRaises(publisher.HandlerNotActiveError):
            publisher.lambda_handler({'unexpected':'input'},object())
        client.assert_not_called()
