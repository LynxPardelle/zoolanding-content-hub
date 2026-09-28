import copy
from pathlib import Path
import unittest
import yaml
from tools.prepare_thn_production_template import prepare_template
ROOT=Path(__file__).resolve().parents[1]
class ProductionTemplateTests(unittest.TestCase):
    def source(self): return yaml.safe_load((ROOT/'template.yaml').read_text())
    def test_shared_v1_resources_are_preserved_and_only_private_routes_rebound(self):
        source=self.source();result=prepare_template(source)
        for logical,value in source['Resources'].items():
            if not logical.startswith(('Thn','ServiceBinding')) and logical!='ContentHubApi': self.assertEqual(result['Resources'][logical],value,logical)
        self.assertEqual(set(result['Resources']['ContentHubApi']['Properties']['DefinitionBody']['paths']),set(source['Resources']['ContentHubApi']['Properties']['DefinitionBody']['paths']))
    def test_production_state_is_retained_closed_and_separately_namespaced(self):
        result=prepare_template(self.source());body=yaml.safe_dump(result)
        for marker in ('zoolanding-content-hub-test','zoolanding-auth-admin-test','zoolanding-image-upload-test','#test#','private/test/'):
            self.assertNotIn(marker,body)
        for parameter in ('EnableThnContentHubV2','ProvisionThnContentHubV2State','ProvisionThnServiceBindingRegistryV2State'):
            self.assertEqual(result['Parameters'][parameter]['Default'],'false')
        for logical,value in result['Resources'].items():
            if logical.startswith(('Thn','ServiceBinding')) and value['Type'] in {'AWS::DynamoDB::Table','AWS::S3::Bucket'}:
                self.assertEqual(value['DeletionPolicy'],'Retain',logical);self.assertEqual(value['UpdateReplacePolicy'],'Retain',logical)
        props=result['Resources']['ThnContentHubV2AuthoringFunction']['Properties']
        self.assertEqual(props['AutoPublishAlias'],'production');self.assertEqual(props['Environment']['Variables']['THN_DEPLOYMENT_ENVIRONMENT'],'production')
    def test_rejects_unknown_private_identity_and_does_not_mutate_source(self):
        source=self.source();before=copy.deepcopy(source);prepare_template(source);self.assertEqual(source,before)
        source['Resources']['ThnContentHubV2AuthoringFunction']['Properties']['FunctionName']='zoolanding-unknown-test-function'
        with self.assertRaises(ValueError): prepare_template(source)

    def test_native_sam_translation_closed_and_active(self):
        import os
        from unittest.mock import patch
        from samtranslator.translator.transform import transform
        for enabled in ('false','true'):
            candidate=prepare_template(self.source())
            for item in candidate['Resources'].values():
                if item['Type']=='AWS::Serverless::Function':
                    item['Properties']['CodeUri']={'Bucket':'synthetic-package','Key':'reviewed.zip','Version':'synthetic-version'}
            parameters={name:value.get('Default') for name,value in candidate['Parameters'].items() if 'Default' in value}
            parameters.update(ThnProductionDependencyGate='CONFIRMED_PRODUCTION_BINDINGS')
            for name in parameters:
                if name.startswith('ProvisionThn'): parameters[name]='true'
                elif name.startswith('EnableThn'): parameters[name]=enabled
                elif 'TerminationProtectionGate' in name: parameters[name]='CONFIRMED_ENABLED'
                elif 'DescriptorVersionId' in name or 'AuthPolicyVersion' in name: parameters[name]='synthetic-production-v1'
                elif 'Sha256' in name: parameters[name]='a'*64
            if 'EnvironmentName' in parameters:
                parameters.update(EnvironmentName='prod',AuthSessionTableName='synthetic-v1-session',AuthUserStateTableName='synthetic-v1-state')
            with patch.dict(os.environ,{'AWS_DEFAULT_REGION':'us-east-1'}):
                native=transform(candidate,parameters,{'AWSLambdaBasicExecutionRole':'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'})
            self.assertNotIn('Transform',native)
            self.assertTrue(all(not item['Type'].startswith('AWS::Serverless::') for item in native['Resources'].values()))

            def refs(value):
                if isinstance(value,dict):
                    if 'Ref' in value and isinstance(value['Ref'],str): yield value['Ref']
                    if 'Fn::GetAtt' in value:
                        target=value['Fn::GetAtt']
                        yield target[0] if isinstance(target,list) else target.split('.')[0]
                    if 'Fn::Sub' in value:
                        import re
                        sub=value['Fn::Sub'];expr=sub if isinstance(sub,str) else sub[0]
                        local=set() if isinstance(sub,str) else set(sub[1])
                        for token in re.findall(r'\$\{([^}!]+)\}',expr):
                            head=token.split('.')[0]
                            if head not in local: yield head
                    for child in value.values(): yield from refs(child)
                elif isinstance(value,list):
                    for child in value: yield from refs(child)
            known=set(native['Resources'])|set(native.get('Parameters',{}))
            dangling={ref for ref in refs(native['Resources']) if not ref.startswith('AWS::') and ref not in known}
            self.assertEqual(dangling,set())
    def test_registry_operator_human_role_is_closed_and_separate(self):
        candidate=prepare_template(self.source())
        role=candidate['Resources']['ThnProductionRegistryHumanOperatorRole']
        self.assertEqual(role['Properties']['RoleName'],'zoolanding-thn-registry-production-operator')
        self.assertEqual(role['Properties']['AssumeRolePolicyDocument']['Statement'][0]['Condition']['Bool'],{'aws:MultiFactorAuthPresent':'true'})
        self.assertEqual(candidate['Parameters']['ProvisionThnProductionRegistryOperator']['Default'],'false')
        self.assertEqual(candidate['Parameters']['ThnProductionRegistryHumanPrincipalArn']['Default'],'BLOCKED')
        self.assertEqual(candidate['Resources']['ServiceBindingRegistryOperatorInvokePolicy']['Properties']['Roles'],[{'Ref':'ThnProductionRegistryHumanOperatorRole'}])
