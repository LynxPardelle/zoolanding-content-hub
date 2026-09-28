import unittest
from production_owner_writer_fence import owner_conditions,WriterFenceError
class ProductionWriterFenceTests(unittest.TestCase):
    def valid(self):
        scope={'environment':'production','domain':'thehairnarrative.com','tenantId':'thehairnarrative-com','hubId':'thehairnarrative-com-journal','authProfileId':'journal-owner','serviceBindingId':'thn-journal-production-v2'}
        binding={'subject':'owner-subject','accountPurpose':'client-owner','scope':scope}
        state={**binding,'sessionVersion':7,'enabled':True}
        user={'Username':'owner-provider-handle','Enabled':True,'UserStatus':'CONFIRMED','UserMFASettingList':['SOFTWARE_TOKEN_MFA'],'PreferredMfaSetting':'SOFTWARE_TOKEN_MFA','UserAttributes':[{'Name':'sub','Value':'owner-subject'}]}
        return binding,state,user
    def test_owner_mfa_is_required_and_state_fenced_atomically(self):
        binding,state,user=self.valid();conditions=owner_conditions(binding,state,user)
        self.assertEqual(len(conditions),2)
        state_check=conditions[1]['ConditionCheck']
        self.assertEqual(state_check['TableName'],'zoolanding-auth-admin-prod-ThnCurrentUserStateV2')
        self.assertIn('#sessionVersion = :version',state_check['ConditionExpression'])
        self.assertIn('#enabled = :enabled',state_check['ConditionExpression'])
    def test_test_qa_disabled_unconfirmed_and_missing_mfa_are_rejected(self):
        for where,key,value in [('binding','accountPurpose','qa'),('state','enabled',False),('state','sessionVersion',True),('user','UserStatus','FORCE_CHANGE_PASSWORD'),('user','UserMFASettingList',[]),('user','Enabled',False)]:
            binding,state,user=self.valid();{'binding':binding,'state':state,'user':user}[where][key]=value
            with self.assertRaises(WriterFenceError): owner_conditions(binding,state,user)
        binding,state,user=self.valid();binding['scope']={**binding['scope'],'environment':'test'}
        with self.assertRaises(WriterFenceError):owner_conditions(binding,state,user)
    def test_registry_cli_rejects_cross_environment_safe_results(self):
        import os,subprocess,sys
        code='''from tools.service_binding_registry_production_operator import _safe_result,OperatorServiceError
row={'ok':True,'operation':'update','environment':'production','domain':'thehairnarrative.com','serviceBindingId':'thn-journal-production-v2','descriptorVersionId':'prod-v1','registryRevision':3}
assert _safe_result(row)['environment']=='production'
for key,value in [('environment','test'),('serviceBindingId','thn-journal-test-v2'),('domain','other.example')]:
 try:_safe_result({**row,key:value})
 except OperatorServiceError:pass
 else:raise AssertionError('cross environment result accepted')
'''
        result=subprocess.run([sys.executable,'-c',code],env={**os.environ,'THN_DEPLOYMENT_ENVIRONMENT':'production'},capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_registry_writer_fence_is_not_reused_by_next_disable(self):
        from unittest.mock import Mock,patch
        import service_binding_registry_operator_lambda as mutation
        from tests.test_service_binding_registry_operator_lambda import AUDIT_CONTEXT
        from tests.test_service_binding_registry_v2 import build_record,audit_context
        import service_binding_registry_v2 as registry
        # Scope/key validation belongs to the registry contract; exercise actual
        # transaction assembly twice, without mirroring the expression builder.
        client=Mock();store=mutation.DynamoDbRegistryStore(client)
        binding={'writerMode':'client-owner'};reservation={};audit={};expected={k:1 for k in mutation._EXPECTED_CONDITIONAL_FIELDS}
        with patch.object(mutation,'PROFILE',{'environment':'production'}),patch.object(mutation,'_require_exact_binding_key'),patch.object(mutation,'_require_exact_reservation_key'),patch.object(mutation,'_require_exact_audit_key'),patch.object(mutation,'_condition_check_for_exact_item',return_value={}),patch.object(mutation,'_append_only_put',return_value={}),patch.object(mutation,'_transaction_token',return_value='fixed'),patch('production_owner_writer_fence.verify_owner',return_value=[{'ConditionCheck':{'TableName':'owner-state'}}]) as verify:
            store.transact_replace_binding(binding,reservation,expected,audit)
            self.assertEqual(len(client.transact_write_items.call_args.kwargs['TransactItems']),4)
            store.transact_replace_binding({'writerMode':'disabled'},reservation,expected,audit)
            self.assertEqual(len(client.transact_write_items.call_args.kwargs['TransactItems']),3)
            self.assertEqual(verify.call_count,1)

    def test_deployed_dependencies_require_real_production_versions_and_origin_fence(self):
        from unittest.mock import Mock
        from production_owner_writer_fence import verify_dependencies,DEPENDENCIES
        session=Mock();cf=Mock();lam=Mock();session.client.side_effect=lambda name: {'cloudformation':cf,'lambda':lam}[name]
        cf.describe_stack_resource.side_effect=lambda **kw: {'StackResourceDetail':{'PhysicalResourceId':'production-'+kw['LogicalResourceId']}}
        lam.get_alias.return_value={'Name':'production','FunctionVersion':'1'}
        config={'State':'Active','LastUpdateStatus':'Successful','Environment':{'Variables':{'THN_DEPLOYMENT_ENVIRONMENT':'production','THN_AUTH_V2_ORIGIN_HEADER_SHA256_CURRENT':'a'*64}}}
        lam.get_function_configuration.return_value=config
        verify_dependencies(session)
        self.assertEqual(cf.describe_stack_resource.call_count,len(DEPENDENCIES))
        self.assertEqual(lam.get_alias.call_count,3)
        for version in ('0','$LATEST','test'):
            lam.get_alias.return_value={'Name':'production','FunctionVersion':version}
            with self.assertRaises(WriterFenceError):verify_dependencies(session)
        lam.get_alias.return_value={'Name':'production','FunctionVersion':'1'}
        for variables in ({'THN_DEPLOYMENT_ENVIRONMENT':'test'},{'THN_DEPLOYMENT_ENVIRONMENT':'production','THN_AUTH_V2_ORIGIN_HEADER_SHA256_CURRENT':'0'*64}):
            lam.get_function_configuration.return_value={**config,'Environment':{'Variables':variables}}
            with self.assertRaises(WriterFenceError):verify_dependencies(session)
