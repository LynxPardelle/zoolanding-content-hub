from pathlib import Path
from unittest import TestCase
import yaml
from tools.build_lambda_artifact import SOURCE_ALLOWLIST, RUNTIME_REQUIREMENTS

ROOT=Path(__file__).resolve().parents[1]


class PublicationWiringTests(TestCase):
    def setUp(self):
        self.template=yaml.safe_load((ROOT/'template.yaml').read_text())
        self.resources=self.template['Resources']

    def statements(self, name):
        return self.resources[name]['Properties']['Policies'][0]['PolicyDocument']['Statement']

    def test_publisher_artifact_contains_atomic_store_not_authoring_transport(self):
        files=set(SOURCE_ALLOWLIST['ThnContentHubV2PublisherFunction'])
        self.assertIn('content_hub_v2_finalization.py',files)
        self.assertIn('content_hub_v2_state_keys.py',files)
        self.assertTrue(files.isdisjoint({'lambda_function.py','content_hub_v2_authoring_handler.py',
            'content_hub_v2_editor_store.py','content_hub_v2_editor_service.py','content_hub_v2_publication_gateway.py'}))
        self.assertIn('ThnContentHubV2PublisherFunction',RUNTIME_REQUIREMENTS)
        authoring=set(SOURCE_ALLOWLIST['ThnContentHubV2AuthoringFunction'])
        self.assertIn('content_hub_v2_publication_gateway.py',authoring)
        self.assertNotIn('publisher_lambda.py',authoring)
        self.assertEqual(SOURCE_ALLOWLIST['ContentHubFunction'],('lambda_function.py',))

    def test_publisher_has_exact_current_user_and_transaction_permissions(self):
        statements={s['Sid']:s for s in self.statements('ThnContentHubV2PublisherRole')}
        user=statements.get('ReadExactThnPublicationActor')
        self.assertIsNotNone(user)
        self.assertEqual(user['Action'],['dynamodb:GetItem'])
        self.assertTrue(user['Resource']['Fn::Sub'].endswith('/zoolanding-auth-admin-test-ThnCurrentUserStateV2'))
        private=statements.get('CommitExactThnPrivatePublication')
        self.assertIsNotNone(private)
        self.assertEqual(private['Condition']['StringEquals']['dynamodb:EnclosingOperation'],'TransactWriteItems')
        self.assertIn('dynamodb:ConditionCheckItem',private['Action'])
        session=statements['CheckExactThnPublishingSession']
        self.assertEqual(session['Action'],['dynamodb:ConditionCheckItem'])
        self.assertTrue(all('dynamodb:Scan' not in s.get('Action',[]) for s in statements.values()))
        for s in statements.values():
            if s is not session: self.assertNotIn('ThnSessionV2',str(s))
        self.assertNotIn('s3:DeleteObject',str(list(statements.values())))

    def test_authoring_invokes_only_publisher_test_alias_and_defaults_stay_closed(self):
        statements=self.statements('ThnContentHubV2AuthoringRole')
        invoke=next(s for s in statements if s['Sid']=='InvokeExactThnPublishAndUpload')
        self.assertIn({'Ref':'ThnContentHubV2PublisherFunction.Alias'},invoke['Resource'])
        props=self.resources['ThnContentHubV2AuthoringFunction']['Properties']
        self.assertEqual(props['Environment']['Variables']['THN_CONTENT_HUB_PUBLISHER_ARN'],{'Ref':'ThnContentHubV2PublisherFunction.Alias'})
        publisher=self.resources['ThnContentHubV2PublisherFunction']['Properties']
        self.assertNotIn('Events',publisher)
        self.assertIn('THN_CONTENT_HUB_DESCRIPTOR_SHA256',publisher['Environment']['Variables'])
        for parameter in ('EnableThnContentHubV2','ProvisionThnContentHubV2State'):
            self.assertEqual(str(self.template['Parameters'][parameter]['Default']).lower(),'false')

    def test_publication_audit_can_only_be_appended_in_the_atomic_transaction(self):
        statements={s['Sid']:s for s in self.statements('ThnContentHubV2PublisherRole')}
        write=statements['AppendExactThnPublishAudit']
        self.assertEqual(write['Action'],['dynamodb:PutItem'])
        self.assertEqual(write['Condition']['StringEquals']['dynamodb:EnclosingOperation'],'TransactWriteItems')
        self.assertEqual(statements['ReadExactThnPublishAudit']['Action'],['dynamodb:GetItem'])
