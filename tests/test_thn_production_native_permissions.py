import json
from pathlib import Path
import unittest
from tools.thn_production_native_permissions import selected_actions, prove_event_rule_resources
from tools.thn_production_release import ReleaseError
class NativePermissionProfileTests(unittest.TestCase):
    def test_event_rule_physical_proof_excludes_pass_role(self):
        logical='ThnContentHubV2InvalidationWorkerFunctionInvalidationSchedule'
        stack='zoolanding-content-hub-prod'
        prefix=f'{stack[:25]}-{logical[:25]}-'
        concrete=f'arn:aws:events:us-east-1:765932874577:rule/{prefix}'+'A'*12
        execution='arn:aws:iam::765932874577:role/zoolanding-deployer-content-hub-production-cfn-exec'
        events={'events:DescribeRule','events:PutRule'}
        actions=events | {'iam:PassRole'}
        request={'principalArn':execution,'actions':sorted(events),
                 'resources':[f'arn:aws:events:us-east-1:765932874577:rule/{prefix}*'],
                 'context':[{'ContextKeyName':'aws:RequestedRegion','ContextKeyValues':['us-east-1'],
                             'ContextKeyType':'string'}]}
        changes=[{'ResourceChange':{'Action':'Add','LogicalResourceId':logical,
                                    'ResourceType':'AWS::Events::Rule'}}]
        template={'Resources':{logical:{'Properties':{'ScheduleExpression':'rate(1 minute)'}}}}
        class IAM:
            def __init__(self):self.calls=[]
            def simulate_principal_policy(self,**kwargs):
                self.calls.append(kwargs)
                return {'EvaluationResults':[{'EvalActionName':action,'EvalDecision':'allowed',
                    'EvalResourceName':concrete} for action in kwargs['ActionNames']]}
        iam=IAM()
        proof=prove_event_rule_resources(iam,[request],execution,actions,changes,template,stack)
        self.assertEqual(len(proof),1)
        self.assertEqual(iam.calls[0]['ResourceArns'],[concrete])
        self.assertEqual(set(iam.calls[0]['ActionNames']),{action.lower() for action in events})

    def test_generated_event_rule_uses_truncated_physical_name_in_iam_proof(self):
        logical='ThnContentHubV2PreparedOrphanCollectorFunctionCollectionSchedule'
        stack='zoolanding-content-hub-prod'
        concrete=f'arn:aws:events:us-east-1:765932874577:rule/{stack[:25]}-{logical[:25]}-'+'A'*12
        actions={'events:DescribeRule','events:PutRule'}
        changes=[{'ResourceChange':{'Action':'Add','LogicalResourceId':logical,'ResourceType':'AWS::Events::Rule'}}]
        template={'Resources':{logical:{'Properties':{'ScheduleExpression':'rate(1 day)','State':'DISABLED'}}}}
        execution='arn:aws:iam::765932874577:role/zoolanding-deployer-content-hub-production-cfn-exec'
        context=[{'ContextKeyName':'aws:RequestedRegion','ContextKeyValues':['us-east-1'],'ContextKeyType':'string'}]
        class IAM:
            def __init__(self):self.calls=[]
            def simulate_principal_policy(self,**kwargs):
                self.calls.append(kwargs)
                return {'EvaluationResults':[{'EvalActionName':action,'EvalDecision':'allowed',
                    'EvalResourceName':concrete} for action in kwargs['ActionNames']]}
        old={'principalArn':execution,'actions':sorted(actions),'context':context,
             'resources':[f'arn:aws:events:us-east-1:765932874577:rule/{stack}-{logical}-*']}
        iam=IAM()
        with self.assertRaisesRegex(ReleaseError,'production_event_rule_resource_unproven'):
            prove_event_rule_resources(iam,[old],execution,actions,changes,template,stack)
        self.assertEqual(iam.calls,[])
        current={**old,'resources':[concrete[:-12]+'*']}
        proof=prove_event_rule_resources(iam,[current],execution,actions,changes,template,stack)
        self.assertEqual(iam.calls[0]['ResourceArns'],[concrete])
        self.assertEqual(len(proof),1)
        class DeniedIAM(IAM):
            def simulate_principal_policy(self,**kwargs):
                result=super().simulate_principal_policy(**kwargs)
                result['EvaluationResults'][0]['EvalDecision']='implicitDeny'
                return result
        with self.assertRaisesRegex(ReleaseError,'production_event_rule_effective_permission_denied'):
            prove_event_rule_resources(DeniedIAM(),[current],execution,actions,changes,template,stack)
        changed=[{'ResourceChange':{**changes[0]['ResourceChange'],'Action':'Modify',
                                    'PhysicalResourceId':concrete.rsplit('/',1)[1]}}]
        self.assertEqual(len(prove_event_rule_resources(IAM(),[current],execution,actions,changed,template,stack)),1)
        changed[0]['ResourceChange']['PhysicalResourceId']='unexpected-rule-name'
        with self.assertRaisesRegex(ReleaseError,'production_event_rule_physical_name_unreviewed'):
            prove_event_rule_resources(IAM(),[current],execution,actions,changed,template,stack)

    def test_lambda_core_uses_captured_handlers_without_unselected_features(self):
        schema={'read':{'permissions':['lambda:GetFunction','kms:Decrypt']},'create':{'permissions':['lambda:CreateFunction','s3:GetObject','ec2:DescribeVpcs','kms:CreateGrant','lambda:GetLayerVersion','lambda:GetCodeSigningConfig','s3files:ListMountTargets']},'delete':{'permissions':['lambda:DeleteFunction','ec2:DescribeNetworkInterfaces']}}
        change={'Action':'Add','LogicalResourceId':'Fn','ResourceType':'AWS::Lambda::Function'}
        template={'Resources':{'Fn':{'Properties':{'FunctionName':'exact','Code':{'S3Bucket':'private','S3Key':'sealed'},'Role':'exact'}}}}
        actions=selected_actions('AWS::Lambda::Function',schema,[change],template)
        self.assertEqual(actions,{'lambda:GetFunction','lambda:CreateFunction','lambda:DeleteFunction','s3:GetObject'})
        template['Resources']['Fn']['Properties']['KmsKeyArn']='unreviewed'
        with self.assertRaises(ReleaseError):selected_actions('AWS::Lambda::Function',schema,[change],template)
    def test_policy_role_only_does_not_require_user_or_group_writes(self):
        schema={'create':{'permissions':['iam:PutRolePolicy','iam:PutUserPolicy','iam:PutGroupPolicy']},'delete':{'permissions':['iam:DeleteRolePolicy','iam:DeleteUserPolicy','iam:DeleteGroupPolicy']}}
        change={'Action':'Add','LogicalResourceId':'Policy','ResourceType':'AWS::IAM::Policy'}
        template={'Resources':{'Policy':{'Properties':{'Roles':['exact']}}}}
        self.assertEqual(selected_actions('AWS::IAM::Policy',schema,[change],template),{'iam:PutRolePolicy','iam:DeleteRolePolicy'})
    def test_unsupported_native_handler_or_missing_resource_fails_closed(self):
        with self.assertRaises(ReleaseError):selected_actions('AWS::Lambda::Function',{},[{'Action':'Add','LogicalResourceId':'Missing'}],{'Resources':{}})
    def test_logs_and_cognito_ignore_unconfigured_cross_service_features(self):
        for kind,fields,permissions in [('AWS::Logs::LogGroup',{'LogGroupName':'/aws/lambda/exact'},['logs:CreateLogGroup','firehose:TagDeliveryStream','s3:REST.PUT.OBJECT','kms:Decrypt']),('AWS::Cognito::UserPool',{'MfaConfiguration':'ON'},['cognito-idp:CreateUserPool','kms:CreateGrant','iam:CreateServiceLinkedRole'])]:
            change={'Action':'Add','LogicalResourceId':'Owned','ResourceType':kind}
            native={'Resources':{'Owned':{'Properties':fields}}}
            result=selected_actions(kind,{'create':{'permissions':permissions}},[change],native)
            self.assertTrue(all(a.startswith('logs:' if kind.endswith('LogGroup') else 'cognito-idp:') for a in result))

    def test_log_group_lifecycle_keeps_core_permissions_from_live_provider(self):
        handlers=json.loads((Path(__file__).parent/'fixtures/production_log_group_handler_permissions.json').read_text())['handlers']
        core_read={'logs:DescribeLogGroups','logs:ListTagsForResource','logs:GetDataProtectionPolicy','logs:DescribeIndexPolicies','logs:DescribeResourcePolicies'}
        expected={
            'Add': core_read | {'logs:CreateLogGroup','logs:PutRetentionPolicy','logs:TagResource','logs:DeleteLogGroup','logs:DeleteDataProtectionPolicy'},
            'Modify': core_read | {'logs:PutRetentionPolicy','logs:DeleteRetentionPolicy','logs:TagResource','logs:UntagResource'},
            'Remove': core_read | {'logs:DeleteLogGroup','logs:DeleteDataProtectionPolicy'},
        }
        template={'Resources':{'Log':{'Properties':{'LogGroupName':'/aws/lambda/exact','RetentionInDays':30}}}}
        for operation,actions in expected.items():
            with self.subTest(operation=operation):
                result=selected_actions('AWS::Logs::LogGroup',handlers,[{'Action':operation,'LogicalResourceId':'Log'}],{} if operation=='Remove' else template,template if operation!='Add' else None)
                self.assertEqual(result,actions)

    def test_log_group_unreviewed_features_in_old_or_new_template_fail_closed(self):
        handlers={'read':{'permissions':['logs:DescribeLogGroups']},'update':{'permissions':['logs:PutRetentionPolicy']}}
        features={'KmsKeyId':'key','DataProtectionPolicy':{'Statement':[{}]},'FieldIndexPolicies':[{}],
            'DeliveryDestinationConfiguration':{'Arn':'delivery'},'ResourcePolicyDocument':{'Statement':[{}]},
            'BearerTokenAuthenticationEnabled':True,'DeletionProtectionEnabled':True,'LogGroupClass':'DELIVERY'}
        for name,value in features.items():
            for previous in (False,True):
                with self.subTest(feature=name,previous=previous):
                    core={'Resources':{'Log':{'Properties':{'LogGroupName':'/aws/lambda/exact'}}}}
                    feature={'Resources':{'Log':{'Properties':{'LogGroupName':'/aws/lambda/exact',name:value}}}}
                    # An explicit clear in the new template must not hide an old feature.
                    cleared={'Resources':{'Log':{'Properties':{'LogGroupName':'/aws/lambda/exact',name:False}}}}
                    with self.assertRaisesRegex(ReleaseError,'production_native_log_feature_not_reviewed'):
                        selected_actions('AWS::Logs::LogGroup',handlers,[{'Action':'Modify','LogicalResourceId':'Log'}],cleared if previous else feature,feature if previous else core)
