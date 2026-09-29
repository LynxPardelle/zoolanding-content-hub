"""Offline retained, closed production projection; never calls AWS."""
from copy import deepcopy
import json
import sys
from pathlib import Path

_ANCHORS=(
 ('zoolanding-content-hub-test-deploy','zoolanding-content-hub-production-deploy'),
 ('zoolanding-content-hub-test','zoolanding-content-hub-prod'),
 ('zoolanding-auth-admin-test','zoolanding-auth-admin-prod'),
 ('zoolanding-image-upload-test','zoolanding-image-upload-production'),
 ('zoolanding-thn-registry-test-','zoolanding-thn-registry-production-'),
 ('zoolanding-thn-content-hub-test-','zoolanding-thn-content-hub-production-'),
 ('zoolanding-deployer-image-upload-test-','zoolanding-deployer-image-upload-production-'),
 ('zlp-thn-ch-test-','zlp-thn-ch-production-'),
 ('zlp-thn-private-upload-test-','zlp-thn-private-upload-production-'),
 ('thn-journal-test-v2','thn-journal-production-v2'),
 ('#test#','#production#'),('private/test/','private/production/'),
 (':test',':production'),('Aliastest','Aliasproduction'),
)

def _bind_production_rules(rules):
    """Compile the exact operator equality; CloudFormation Rules cannot use Fn::Sub."""
    expected={'Fn::Equals':[
        {'Ref':'ThnContentHubV2EmergencyOperatorRoleArn'},
        {'Fn::Sub':'arn:${AWS::Partition}:iam::${AWS::AccountId}:role/zoolanding-thn-content-hub-production-operator'}]}
    assertion=rules['ThnContentHubV2ActivationRule']['Assertions'][3]['Assert']
    if assertion != expected:
        raise ValueError('production_operator_rule_shape_invalid')
    assertion['Fn::Equals'][1]='arn:aws:iam::765932874577:role/zoolanding-thn-content-hub-production-operator'
    supported={'Fn::And','Fn::Contains','Fn::EachMemberEquals','Fn::EachMemberIn',
               'Fn::Equals','Fn::Not','Fn::Or','Fn::RefAll','Fn::ValueOf','Fn::ValueOfAll'}
    def inspect(value):
        if isinstance(value,dict):
            for key,child in value.items():
                if key.startswith('Fn::') and key not in supported:
                    raise ValueError('production_rule_function_unsupported')
                inspect(child)
        elif isinstance(value,list):
            for child in value: inspect(child)
    inspect(rules)

def _project(value, sam=False):
    if isinstance(value,dict): return {key:_project(item,sam) for key,item in value.items()}
    if isinstance(value,list): return [_project(item,sam) for item in value]
    if not isinstance(value,str): return value
    if value=='test': return 'prod' if sam else 'production'
    for old,new in _ANCHORS: value=value.replace(old,new)
    if '-test-' in value or '#test#' in value or 'private/test/' in value or 'admin-test.' in value:
        raise ValueError('production_source_identity_unrecognized')
    return value

def prepare_template(source):
    if not isinstance(source,dict) or source.get('Transform')!='AWS::Serverless-2016-10-31' or not {'ServiceBindingRegistryV2Table','ThnContentHubV2AuthoringFunction','ContentHubApi'}.issubset(source.get('Resources',{})):
        raise ValueError('production_source_resources_invalid')
    result=deepcopy(source)
    for name,value in result['Parameters'].items():
        if name.startswith(('Thn','ServiceBinding')): result['Parameters'][name]=_project(value)
    result['Parameters']['EnvironmentName']['Default']='prod';result['Parameters']['EnvironmentName']['AllowedValues']=['prod']
    result['Parameters']['ProvisionThnServiceBindingRegistryV2State']={'Type':'String','Default':'false','AllowedValues':['false','true']}
    result['Parameters']['ThnProductionDependencyGate']={'Type':'String','Default':'BLOCKED','AllowedValues':['BLOCKED','CONFIRMED_PRODUCTION_BINDINGS']}
    result['Rules']=_project(result['Rules'],True);_bind_production_rules(result['Rules'])
    result['Conditions']=_project(result['Conditions'],True)
    result['Conditions']['IsThnProductionRegistryStateProvisioned']={'Fn::And':[{'Condition':'IsTestEnvironment'},{'Fn::Equals':[{'Ref':'ProvisionThnServiceBindingRegistryV2State'},'true']}]}
    result['Conditions']['HasServiceBindingRegistryOperatorRole']['Fn::And'].append({'Condition':'IsThnProductionRegistryStateProvisioned'})
    result['Rules']['ThnContentHubV2StateProvisioningRule']['Assertions'].append({'Assert':{'Fn::Equals':[{'Ref':'ProvisionThnServiceBindingRegistryV2State'},'true']},'AssertDescription':'Retained production registry state must be selected independently.'})
    result['Rules']['ThnContentHubV2ActivationRule']['Assertions'].append({'Assert':{'Fn::Equals':[{'Ref':'ThnProductionDependencyGate'},'CONFIRMED_PRODUCTION_BINDINGS']},'AssertDescription':'Verify production auth, image processor, registry and distribution bindings before activating routes.'})
    for logical,value in list(result['Resources'].items()):
        if not logical.startswith(('Thn','ServiceBinding')) and logical!='ContentHubApi': continue
        projected=_project(value)
        if projected.get('Condition')=='IsTestEnvironment': projected['Condition']='IsThnProductionRegistryStateProvisioned'
        if projected.get('Type')=='AWS::Serverless::Function':
            projected['Properties'].setdefault('Environment',{}).setdefault('Variables',{})['THN_DEPLOYMENT_ENVIRONMENT']='production'
        result['Resources'][logical]=projected
    result['Parameters']['ThnProductionOwnerPoolArn']={'Type':'String','Default':'BLOCKED','NoEcho':True,'AllowedPattern':'^(BLOCKED|arn:aws:cognito-idp:us-east-1:765932874577:userpool/us-east-1_[A-Za-z0-9]+)$'}
    result['Conditions']['HasThnProductionOwnerPoolArn']={'Fn::Not':[{'Fn::Equals':[{'Ref':'ThnProductionOwnerPoolArn'},'BLOCKED']}]}
    result['Resources']['ServiceBindingRegistryV2MutationFunction']['Properties']['Environment']['Variables']['THN_PRODUCTION_OWNER_POOL_ARN']={'Ref':'ThnProductionOwnerPoolArn'}
    statements=result['Resources']['ServiceBindingRegistryV2MutationRole']['Properties']['Policies'][0]['PolicyDocument']['Statement']
    statements.extend([
        {'Sid':'ResolveExactProductionOwnerPool','Effect':'Allow','Action':['cloudformation:DescribeStackResource'],'Resource':{'Fn::Sub':'arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/zoolanding-auth-admin-prod/*'}},
        {'Sid':'ReadExactProductionOwnerState','Effect':'Allow','Action':['dynamodb:GetItem'],'Resource':{'Fn::Sub':'arn:${AWS::Partition}:dynamodb:${AWS::Region}:${AWS::AccountId}:table/zoolanding-auth-admin-prod-ThnCurrentUserStateV2'},'Condition':{'ForAllValues:StringEquals':{'dynamodb:LeadingKeys':['CURRENT_USER#production#thn-journal-production-v2']}}},
        {'Sid':'FenceExactProductionOwnerState','Effect':'Allow','Action':['dynamodb:ConditionCheckItem'],'Resource':{'Fn::Sub':'arn:${AWS::Partition}:dynamodb:${AWS::Region}:${AWS::AccountId}:table/zoolanding-auth-admin-prod-ThnCurrentUserStateV2'},'Condition':{'ForAllValues:StringEquals':{'dynamodb:LeadingKeys':['CURRENT_USER#production#thn-journal-production-v2']},'StringEquals':{'dynamodb:EnclosingOperation':'TransactWriteItems'},'StringEqualsIfExists':{'dynamodb:ReturnValues':'NONE'}}},
        {'Fn::If':['HasThnProductionOwnerPoolArn',{'Sid':'VerifyExactProductionOwnerMfa','Effect':'Allow','Action':['cognito-idp:DescribeUserPool','cognito-idp:GetUserPoolMfaConfig','cognito-idp:ListUsersInGroup','cognito-idp:AdminGetUser'],'Resource':{'Ref':'ThnProductionOwnerPoolArn'}},{'Ref':'AWS::NoValue'}]},
    ])
    statements.extend([
        {'Sid':'ResolveExactProductionWriterServices','Effect':'Allow','Action':['cloudformation:DescribeStackResource'],'Resource':[{'Fn::Sub':'arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/'+name+'/*'} for name in ('zoolanding-content-hub-prod','zoolanding-image-upload','zoolanding-thn-auth-runtime-production')]},
        {'Sid':'ReadExactProductionWriterServices','Effect':'Allow','Action':['lambda:GetFunctionConfiguration','lambda:GetAlias'],'Resource':[{'Fn::Sub':'arn:${AWS::Partition}:lambda:${AWS::Region}:${AWS::AccountId}:function:'+name+suffix} for name in ('zoolanding-auth-admin-prod-ThnAuthAdminV2','zoolanding-auth-prod-ThnV2OriginAuthorizer','zoolanding-content-hub-prod-ThnContentHubV2Authoring','zoolanding-image-upload-production-ThnImageUploadV2','zoolanding-thn-auth-runtime-production-ThnAuthRuntimeV2Function-*') for suffix in ('',':production')]},
    ])
    result['Parameters']['ProvisionThnProductionRegistryOperator']={'Type':'String','Default':'false','AllowedValues':['false','true']}
    result['Parameters']['ThnProductionRegistryHumanPrincipalArn']={'Type':'String','Default':'BLOCKED','AllowedPattern':'^(BLOCKED|arn:aws:iam::765932874577:user/[A-Za-z0-9+=,.@_/-]+)$'}
    result['Conditions']['HasServiceBindingRegistryOperatorRole']={'Fn::And':[{'Condition':'IsThnProductionRegistryStateProvisioned'},{'Fn::Equals':[{'Ref':'ProvisionThnProductionRegistryOperator'},'true']}]}
    result['Rules']['ThnProductionRegistryOperatorRule']={'RuleCondition':{'Fn::Equals':[{'Ref':'ProvisionThnProductionRegistryOperator'},'true']},'Assertions':[{'Assert':{'Fn::Equals':[{'Ref':'ProvisionThnServiceBindingRegistryV2State'},'true']},'AssertDescription':'Registry operator requires separately retained production registry state.'},{'Assert':{'Fn::Not':[{'Fn::Equals':[{'Ref':'ThnProductionRegistryHumanPrincipalArn'},'BLOCKED']}]},'AssertDescription':'The exact MFA-protected human IAM principal requires separate approval.'}]}
    result['Resources']['ThnProductionRegistryHumanOperatorRole']={'Type':'AWS::IAM::Role','Condition':'HasServiceBindingRegistryOperatorRole','DeletionPolicy':'Retain','UpdateReplacePolicy':'Retain','Properties':{'RoleName':'zoolanding-thn-registry-production-operator','MaxSessionDuration':3600,'AssumeRolePolicyDocument':{'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'sts:AssumeRole','Principal':{'AWS':{'Ref':'ThnProductionRegistryHumanPrincipalArn'}},'Condition':{'Bool':{'aws:MultiFactorAuthPresent':'true'},'NumericLessThanEquals':{'aws:MultiFactorAuthAge':'300'}}}]}}}
    result['Resources']['ServiceBindingRegistryOperatorInvokePolicy']['Properties']['Roles']=[{'Ref':'ThnProductionRegistryHumanOperatorRole'}]
    result['Metadata']=_project(result.get('Metadata',{}));result['Metadata']['ThnProductionLifecycle']={'Profile':'production','SAMEnvironment':'prod','AutomaticActivation':False,'RegistryAndWriters':'closed until separately reviewed activation'}
    result['Outputs']=_project(result.get('Outputs',{}))
    return result

def main(argv=None):
    import yaml
    args=sys.argv[1:] if argv is None else argv
    if len(args)!=2: raise ValueError('production_template_arguments_invalid')
    Path(args[1]).write_text(json.dumps(prepare_template(yaml.safe_load(Path(args[0]).read_text(encoding='utf-8'))),sort_keys=True,indent=2)+'\n',encoding='utf-8')
    return 0
if __name__=='__main__': raise SystemExit(main())
