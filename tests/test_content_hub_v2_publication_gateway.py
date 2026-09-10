import importlib.util
import io
import json
from types import SimpleNamespace
from unittest import TestCase
import test_content_hub_v2_publisher as publisher_fixtures
import test_content_hub_v2_editor_http as http_fixtures


class GatewayTests(TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('content_hub_v2_publication_gateway'),
                             'authoring needs a dedicated publisher gateway, not a public store')
        self.module=__import__('content_hub_v2_publication_gateway')
        self.fixture=publisher_fixtures.PublisherTests();self.fixture.setUp()
        self.calls=[]
        self.authorized=0
        def invoke(**kwargs):
            self.calls.append(kwargs)
            result=self.fixture.run_event(json.loads(kwargs['Payload']))
            return {'StatusCode':200,'ExecutedVersion':'7','Payload':io.BytesIO(json.dumps(result).encode())}
        self.gateway=self.module.PublicationGateway(self.fixture.f.auth,'a'*64,
            {'partition':'aws','region':'us-east-1','accountId':'000000000000'},
            self.fixture.context.invoked_function_arn,clock=lambda:self.fixture.f.now,lambda_client=SimpleNamespace(invoke=invoke))
        self.data={'articleId':'a1','locale':'en','concurrencyToken':'edit-r1','revisionId':'r1','idempotencyKey':'1'*32}

    def authorize(self): self.authorized+=1

    def test_real_gateway_invokes_only_test_alias_and_actual_publisher(self):
        result=self.gateway('publish',self.fixture.f.article(),'en',self.authorize,self.data)
        self.assertEqual(result['state'],'published')
        self.assertGreaterEqual(self.authorized,2)
        self.assertEqual(self.calls[0]['FunctionName'],self.fixture.context.invoked_function_arn)
        self.assertEqual(self.calls[0]['InvocationType'],'RequestResponse')
        self.assertEqual(self.gateway('publish',self.fixture.f.article(),'en',self.authorize,self.data),result)

    def test_final_authorize_denial_prevents_invocation(self):
        def denied(): raise RuntimeError('denied')
        with self.assertRaises(RuntimeError):
            self.gateway('publish',self.fixture.f.article(),'en',denied,self.data)
        self.assertEqual(self.calls,[])

    def test_missing_or_wrong_publisher_has_no_direct_storage_fallback(self):
        for binding in ('',self.fixture.context.invoked_function_arn.replace(':test',':prod')):
            with self.assertRaises(Exception):
                self.module.PublicationGateway(self.fixture.f.auth,'a'*64,
                    {'partition':'aws','region':'us-east-1','accountId':'000000000000'},binding)
        self.assertEqual(self.calls,[])

    def test_http_exposes_capability_and_csrf_protects_gateway(self):
        http=http_fixtures.EditorHttpTests();http.setUp()
        calls=[]
        def publish(*args):
            calls.append(args)
            return {'articleId':args[1]['articleId'],'locale':'en','state':'unpublished','concurrencyToken':'safe-ack'}
        http.runtime.get_publisher=lambda *args:publish
        article=json.loads(http.send('createArticle',{'locale':'en'})['body'])['data']
        self.assertTrue(article['publicationAvailable'])
        data={'articleId':article['articleId'],'locale':'en','concurrencyToken':article['concurrencyToken'],'idempotencyKey':'1'*32}
        self.assertEqual(http.send('unpublishArticle',data,csrf=False)['statusCode'],403)
        self.assertEqual(calls,[])
        self.assertEqual(http.send('unpublishArticle',data)['statusCode'],200)
        self.assertEqual(len(calls),1)
