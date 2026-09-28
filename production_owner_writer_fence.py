"""Server-side production writer prerequisite; no email/password transport.

Cognito MFA and the singleton owner are read at the mutation boundary. The
registry transaction checks the exact owner binding and current session version
atomically, so a concurrent disable/reset cannot authorize the writer change.
"""
import os
import re
from thn_environment_profile import PROFILE

TABLE='zoolanding-auth-admin-prod-ThnCurrentUserStateV2'
PARTITION='CURRENT_USER#production#thn-journal-production-v2'
SCOPE={'environment':'production','domain':'thehairnarrative.com','tenantId':'thehairnarrative-com',
    'hubId':'thehairnarrative-com-journal','authProfileId':'journal-owner','serviceBindingId':'thn-journal-production-v2'}

class WriterFenceError(ValueError):pass

def require(value):
    if not value:raise WriterFenceError('production_owner_mfa_prerequisite_missing')

def owner_conditions(binding,state,user):
    from service_binding_registry_operator_lambda import marshal_item
    require(isinstance(binding,dict) and isinstance(state,dict) and isinstance(user,dict))
    subject=binding.get('subject')
    require(isinstance(subject,str) and bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}',subject)))
    require(binding.get('scope')==SCOPE and state.get('scope')==SCOPE and
        binding.get('accountPurpose')=='client-owner' and state.get('accountPurpose')=='client-owner' and
        state.get('subject')==subject and state.get('enabled') is True and
        type(state.get('sessionVersion')) is int and state['sessionVersion']>=1)
    attributes=user.get('UserAttributes',[])
    subjects=[a.get('Value') for a in attributes if a.get('Name')=='sub']
    require(subjects==[subject] and user.get('Enabled') is True and user.get('UserStatus')=='CONFIRMED' and
        user.get('UserMFASettingList')==['SOFTWARE_TOKEN_MFA'] and user.get('PreferredMfaSetting')=='SOFTWARE_TOKEN_MFA')
    base={'TableName':TABLE,'ExpressionAttributeNames':{'#subject':'subject','#accountPurpose':'accountPurpose','#scope':'scope'},
        'ExpressionAttributeValues':marshal_item({':subject':subject,':purpose':'client-owner',':scope':SCOPE}),
        'ConditionExpression':'#subject = :subject AND #accountPurpose = :purpose AND #scope = :scope',
        'ReturnValuesOnConditionCheckFailure':'NONE'}
    owner={**base,'Key':marshal_item({'pk':PARTITION,'sk':'OWNER#client-owner'})}
    current={**base,'Key':marshal_item({'pk':PARTITION,'sk':'SUBJECT#'+subject}),
        'ExpressionAttributeNames':{**base['ExpressionAttributeNames'],'#enabled':'enabled','#sessionVersion':'sessionVersion'},
        'ExpressionAttributeValues':{**base['ExpressionAttributeValues'],**marshal_item({':enabled':True,':version':state['sessionVersion']})},
        'ConditionExpression':base['ConditionExpression']+' AND #enabled = :enabled AND #sessionVersion = :version'}
    return [{'ConditionCheck':owner},{'ConditionCheck':current}]

def verify_owner(dynamodb,session=None):
    require(PROFILE['environment']=='production')
    from service_binding_registry_operator_lambda import marshal_item,unmarshal_item
    if session is None:
        import boto3
        session=boto3.Session(region_name='us-east-1')
    require(session.region_name=='us-east-1')
    cf=session.client('cloudformation')
    resource=cf.describe_stack_resource(StackName='zoolanding-auth-admin-prod',LogicalResourceId='ThnAuthAdminV2UserPool')['StackResourceDetail']
    pool=resource['PhysicalResourceId']
    arn=f'arn:aws:cognito-idp:us-east-1:765932874577:userpool/{pool}'
    require(os.environ.get('THN_PRODUCTION_OWNER_POOL_ARN')==arn)
    cognito=session.client('cognito-idp')
    config=cognito.describe_user_pool(UserPoolId=pool)['UserPool']
    require(config.get('Name')=='zoolanding-auth-admin-prod-ThnAuthAdminV2' and config.get('MfaConfiguration')=='ON' and
        config.get('AdminCreateUserConfig',{}).get('AllowAdminCreateUserOnly') is True)
    mfa=cognito.get_user_pool_mfa_config(UserPoolId=pool)
    require(mfa.get('MfaConfiguration')=='ON' and mfa.get('SoftwareTokenMfaConfiguration',{}).get('Enabled') is True)
    response=cognito.list_users_in_group(UserPoolId=pool,GroupName='journal-owner',Limit=2)
    require(not response.get('NextToken') and len(response.get('Users',[]))==1)
    user=cognito.admin_get_user(UserPoolId=pool,Username=response['Users'][0]['Username'])
    def read(sort_key):
        item=dynamodb.get_item(TableName=TABLE,Key=marshal_item({'pk':PARTITION,'sk':sort_key}),ConsistentRead=True).get('Item')
        require(isinstance(item,dict) and item)
        return unmarshal_item(item)
    binding=read('OWNER#client-owner')
    state=read('SUBJECT#'+binding.get('subject',''))
    conditions=owner_conditions(binding,state,user)
    verify_dependencies(session)
    return conditions
# Deployed alias/controller dependency tuple is server owned, never proposed
# by the operator request. Enable writer only after all production services exist.
DEPENDENCIES=(
 ('zoolanding-auth-admin-prod','ThnAuthAdminV2Function',None),
 ('zoolanding-auth-admin-prod','ThnAuthAdminV2OriginAuthorizerFunction',None),
 ('zoolanding-content-hub-prod','ThnContentHubV2AuthoringFunction','production'),
 ('zoolanding-image-upload','ThnPrivateImageUploadV2Function','production'),
 ('zoolanding-thn-auth-runtime-production','ThnAuthRuntimeV2Function','production'),
)
def verify_dependencies(session):
    cf=session.client('cloudformation');client=session.client('lambda')
    for stack,logical,alias in DEPENDENCIES:
        physical=cf.describe_stack_resource(StackName=stack,LogicalResourceId=logical)['StackResourceDetail']['PhysicalResourceId']
        require(isinstance(physical,str) and physical and '-test-' not in physical)
        kwargs={'FunctionName':physical}
        if alias:
            active=client.get_alias(FunctionName=physical,Name=alias)
            require(active.get('Name')=='production' and bool(re.fullmatch(r'[1-9][0-9]*',str(active.get('FunctionVersion','')))))
            kwargs['Qualifier']=alias
        config=client.get_function_configuration(**kwargs)
        require(config.get('State')=='Active' and config.get('LastUpdateStatus')=='Successful' and
            config.get('Environment',{}).get('Variables',{}).get('THN_DEPLOYMENT_ENVIRONMENT')=='production')
        if logical=='ThnAuthAdminV2OriginAuthorizerFunction':
            digest=config['Environment']['Variables'].get('THN_AUTH_V2_ORIGIN_HEADER_SHA256_CURRENT','')
            require(bool(re.fullmatch('[a-f0-9]{64}',digest)) and digest!='0'*64)
