import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
class ClosedEnvironmentProfileTests(unittest.TestCase):
    def run_profile(self, environment, expression):
        env = dict(os.environ)
        if environment is None:
            env.pop("THN_DEPLOYMENT_ENVIRONMENT", None)
        else:
            env["THN_DEPLOYMENT_ENVIRONMENT"] = environment
        return subprocess.run([sys.executable, "-c", expression], cwd=ROOT, env=env, text=True, capture_output=True)

    def test_test_contract_is_unchanged(self):
        result = self.run_profile(None, "import thn_environment_profile as p; print(p.PROFILE['environment'], p.PROFILE['cookieNamespace'], p.PROFILE['adminHost'])")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "test endefiz7dkk635k6di6k admin-test.thehairnarrative.com")

    def test_production_has_distinct_closed_coordinates(self):
        result = self.run_profile("production", "import thn_environment_profile as p; print(p.PROFILE['environment'], p.PROFILE['samEnvironment'], p.PROFILE['cookieNamespace'], p.PROFILE['registryPartitionKey'], p.PROFILE['authStack'])")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "production prod ltnafwb6videyraictgp SERVICE_BINDING#production#thn-journal-production-v2 zoolanding-auth-admin-prod")

    def test_aliases_and_unknown_environment_fail_closed(self):
        for environment in ("prod", "dev", "Production", "", " production", "test "):
            with self.subTest(environment=environment):
                self.assertNotEqual(self.run_profile(environment, "import thn_environment_profile").returncode, 0)

    def test_profile_is_immutable(self):
        self.assertNotEqual(self.run_profile("production", "from thn_environment_profile import PROFILE; PROFILE['environment']='test'").returncode, 0)

    def test_runtime_coordinates_are_sealed_at_import(self):
        code = "import os; from thn_environment_profile import PROFILE; os.environ['THN_DEPLOYMENT_ENVIRONMENT']='test'; assert PROFILE['environment']=='production'"
        result = self.run_profile("production", code)
        self.assertEqual(result.returncode, 0, result.stderr)


    def test_all_authoring_and_projection_coordinates_use_production(self):
        code="import content_hub_v2_authoring_handler as a, content_hub_v2_state_keys as k, content_hub_v2_projection as p, content_hub_v2_projection_manifest as m, public_media_lambda as media; assert a.ENVIRONMENT=='production'; assert a.COOKIE_NAMESPACE=='ltnafwb6videyraictgp'; assert a.CURRENT_USER_PARTITION_KEY=='CURRENT_USER#production#thn-journal-production-v2'; assert a.AUTHORING_FUNCTION_ALIAS=='production'; assert k.METADATA_TABLE=='zoolanding-content-hub-prod-ThnContentHubV2Metadata'; assert '#production#' in m.MANIFEST_PK; assert p.ROOT.startswith('content-hubs/production/'); assert media.PUBLIC_HOST=='thehairnarrative.com'; assert media.ADMIN_HOST=='admin.thehairnarrative.com'"
        result=self.run_profile('production',code)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_production_actor_policy_excludes_qa(self):
        code="import service_binding_registry_v2 as r, content_hub_v2_authorization as a; assert r.APPROVED_ENVIRONMENT=='production'; assert r.APPROVED_COOKIE_NAMESPACE=='ltnafwb6videyraictgp'; assert r.ALLOWED_WRITER_MODES==frozenset({'disabled','client-owner'}); assert a.ALLOWED_ACCOUNT_PURPOSES==frozenset({'client-owner'}); assert a.ALLOWED_WRITER_MODES==frozenset({'disabled','client-owner'})"
        result=self.run_profile('production',code)
        self.assertEqual(result.returncode,0,result.stderr)
    def test_dynamic_ids_are_never_rewritten_or_rejected_as_environment_coordinates(self):
        code="""from content_hub_v2_private_upload import private_variant_key
from content_hub_v2_editor_model import safe_id
for article in ('client-test-story','thn-journal-test-v2','ordinary'):
 assert safe_id(article)==article
 key=private_variant_key({'articleId':article,'locale':'en','revisionId':'revision-test-one','assetId':'thn-journal-test-v2'},{'variantId':'w480','contentType':'image/png'})
 assert key.startswith('private/production/')
 assert '/articles/'+article+'/' in key
 assert '/revisions/revision-test-one/assets/thn-journal-test-v2/' in key
"""
        result=self.run_profile('production',code)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_coordinate_runtime_calls_only_receive_static_literals(self):
        import ast
        offenders=[]
        for path in ROOT.glob('*.py'):
            for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
                if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='coordinate':
                    if len(node.args)!=1 or not isinstance(node.args[0],ast.Constant) or not isinstance(node.args[0].value,str):offenders.append((path.name,node.lineno))
        self.assertEqual(offenders,[])
