"""Retained native production review. Never repackages during execution.

Source-only main integration is separate from this protected manual operation.
Raw templates/parameters/recovery bytes belong in private versioned S3; the
transported review record contains only identities, fingerprints and inventory.
"""
from copy import deepcopy
import hashlib
import json
import re
import time

ACCOUNT = '765932874577'
REGION = 'us-east-1'
CONTRACT = 'thn-production-retained-review/v1'
FIELDS = frozenset({'schemaVersion','contract','environment','service','purpose',
    'sourceSha','stackId','changeSetArn','createdAt','expiresAt','baselineSha256',
    'originalTemplateSha256','processedTemplateSha256','parametersSha256',
    'permissionSha256','identitySha256','sourcePackageSha256','packageManifest',
    'changes','nativeInventorySha256','recoveryCoordinates','digest'})
PURPOSES = frozenset({'state','activate','general','recover','operator-patch','registry-reader-patch'})
REGISTRY_READER_TABLE = 'ServiceBindingRegistryV2Table'
REGISTRY_READER_TABLE_NAME = 'zoolanding-content-hub-prod-ServiceBindingRegistryV2'
REGISTRY_READER_ROLE = 'arn:aws:iam::765932874577:role/zoolanding-deployer-thn-auth-runtime-production-github-deploy'
REGISTRY_DEPLOY_READERS = (
    'arn:aws:iam::765932874577:role/zoolanding-content-hub-production-deploy',
    'arn:aws:iam::765932874577:role/zoolanding-deployer-image-upload-production-github-deploy',
)
REGISTRY_READER_SIDS = (
    'DenyRegistryGetItemOutsideApprovedConsumers',
    'DenyRegistryDeploymentReadOutsideBinding',
    'DenyRegistryDeploymentReadMissingKeys',
)


def registry_reader_candidate_template(old):
    """Add one exact API role to three policy lists, preserving all other nodes."""
    result=deepcopy(old)
    table=result.get('Resources',{}).get(REGISTRY_READER_TABLE,{})
    require(table.get('Type')=='AWS::DynamoDB::Table',
            'production_registry_reader_table_changed')
    policy=table.get('Properties',{}).get('ResourcePolicy',{}).get('PolicyDocument',{})
    statements=policy.get('Statement')
    require(policy.get('Version')=='2012-10-17' and isinstance(statements,list),
            'production_registry_reader_policy_changed')
    matches=[next((row for row in statements if isinstance(row,dict) and row.get('Sid')==sid),None)
             for sid in REGISTRY_READER_SIDS]
    require(all(row is not None for row in matches) and
            all(sum(isinstance(row,dict) and row.get('Sid')==sid for row in statements)==1
                for sid in REGISTRY_READER_SIDS),
            'production_registry_reader_statements_changed')
    broad,other,missing=matches
    def principal(value):
        if isinstance(value,dict) and value.get('Fn::Sub')==(
                'arn:${AWS::Partition}:iam::${AWS::AccountId}:role/'+REGISTRY_READER_ROLE.split('/')[-1]):
            return True
        return value==REGISTRY_READER_ROLE
    api={'Fn::Sub':'arn:${AWS::Partition}:iam::${AWS::AccountId}:role/'+
         REGISTRY_READER_ROLE.split('/')[-1]} if any(isinstance(v,dict) for v in
         broad.get('Condition',{}).get('ArnNotEquals',{}).get('aws:PrincipalArn',[])) else REGISTRY_READER_ROLE
    readers=broad.get('Condition',{}).get('ArnNotEquals',{}).get('aws:PrincipalArn')
    require(broad.get('Effect')=='Deny' and broad.get('Principal')=='*' and
            broad.get('Action')==['dynamodb:GetItem'] and isinstance(readers,list) and
            len(readers)==13 and len({canonical(v) for v in readers})==13 and
            not any(principal(v) for v in readers),
            'production_registry_reader_approved_consumers_changed')
    for row,condition,expected in (
            (other,'ForAnyValue:StringNotEquals',
             ['SERVICE_BINDING#production#thn-journal-production-v2']),
            (missing,'Null','true')):
        values=row.get('Principal',{}).get('AWS') if isinstance(row.get('Principal'),dict) else None
        resolved=[v.get('Fn::Sub','') if isinstance(v,dict) else v for v in values or []]
        normalized=[value.replace('${AWS::Partition}','aws').replace('${AWS::AccountId}',ACCOUNT)
                    for value in resolved]
        require(row.get('Effect')=='Deny' and row.get('Action')==['dynamodb:GetItem'] and
                isinstance(values,list) and len(values)==2 and
                set(normalized)==set(REGISTRY_DEPLOY_READERS) and
                row.get('Condition')=={condition:{'dynamodb:LeadingKeys':expected}},
                'production_registry_reader_deployment_fence_changed')
        values.append(deepcopy(api))
    readers.append(deepcopy(api))
    return result
OPERATOR_PRINCIPAL = 'arn:aws:iam::765932874577:user/Hector-admin'
OPERATOR_PARAMETERS = {
    'ProvisionThnProductionRegistryOperator': 'true',
    'ThnProductionRegistryHumanPrincipalArn': OPERATOR_PRINCIPAL,
}
OPERATOR_RESOURCES = {
    'ThnProductionRegistryHumanOperatorRole': 'AWS::IAM::Role',
    'ServiceBindingRegistryOperatorInvokePolicy': 'AWS::IAM::Policy',
}
OPERATOR_DORMANT_PERMISSION = 'ServiceBindingRegistryOperatorInvokePermission'

def operator_candidate_template(old):
    """Preserve every deployed template node except the dormant grant."""
    result=deepcopy(old)
    require(isinstance(result,dict) and isinstance(result.get('Resources'),dict) and
        result['Resources'].get(OPERATOR_DORMANT_PERMISSION,{}).get('Type')=='AWS::Lambda::Permission',
        'production_operator_dormant_permission_missing')
    del result['Resources'][OPERATOR_DORMANT_PERMISSION]
    return result
SERVICES = frozenset({'auth','api','hub','image'})
DEPENDENCIES = frozenset({'AWS::Lambda::Permission','AWS::Lambda::Url',
    'AWS::Lambda::ResourcePolicy'})
RESOURCE_TYPES = frozenset({'AWS::Lambda::Function','AWS::Lambda::Version',
    'AWS::Lambda::Alias','AWS::Lambda::Permission','AWS::Lambda::Url',
    'AWS::Lambda::ResourcePolicy','AWS::DynamoDB::Table','AWS::S3::Bucket',
    'AWS::S3::BucketPolicy','AWS::IAM::Role','AWS::IAM::Policy','AWS::Logs::LogGroup',
    'AWS::Cognito::UserPool','AWS::Cognito::UserPoolClient','AWS::Cognito::UserPoolGroup',
    'AWS::ApiGatewayV2::Api','AWS::ApiGatewayV2::Stage','AWS::ApiGatewayV2::Authorizer',
    'AWS::ApiGatewayV2::Integration','AWS::ApiGatewayV2::Route','AWS::ApiGateway::RestApi',
    'AWS::ApiGateway::Stage','AWS::ApiGateway::Deployment','AWS::CloudWatch::Alarm',
    'AWS::SNS::Topic','AWS::SNS::Subscription','AWS::Events::Rule'})

class ReleaseError(ValueError):
    """Sanitized closed-contract failure; never include provider values."""

def require(condition, message='production_release_invalid'):
    if not condition: raise ReleaseError(message)

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),default=str).encode()

def sha(value):
    return hashlib.sha256(value if isinstance(value,bytes) else canonical(value)).hexdigest()

def stable_simulation_evaluations(evaluations):
    """Preserve IAM evidence while ignoring provider ordering of equal results."""
    rows=deepcopy(evaluations)
    for row in rows:
        for key in ('MatchedStatements','MissingContextValues'):
            if key in row:row[key]=sorted(row[key],key=canonical)
        for resource in row.get('ResourceSpecificResults',[]):
            for key in ('MatchedStatements','MissingContextValues'):
                if key in resource:resource[key]=sorted(resource[key],key=canonical)
        if 'ResourceSpecificResults' in row:
            row['ResourceSpecificResults']=sorted(row['ResourceSpecificResults'],key=canonical)
    return sorted(rows,key=canonical)

def _sha(value,length=64):
    return isinstance(value,str) and bool(re.fullmatch('[a-f0-9]{'+str(length)+'}',value)) and value!='0'*length

def safe_inventory(changes):
    """Property contexts may contain Lambda configuration; fingerprint them."""
    return sorted([{'resource':{key:item.get('ResourceChange',{}).get(key) for key in
        ('Action','LogicalResourceId','PhysicalResourceId','ResourceType','Replacement','Scope')},
        'nativeChangeSha256':sha(item)} for item in changes],key=canonical)

def make_review_record(*,service,purpose,source_sha,stack_id,change_set_arn,
        created_at,baseline,original,processed,parameters,packages,changes,recovery,
        permissions=None,identity=None,source_package=None):
    require(service in SERVICES and purpose in PURPOSES and _sha(source_sha,40))
    require(type(created_at) is int)
    record={'schemaVersion':1,'contract':CONTRACT,'environment':'production',
        'service':service,'purpose':purpose,'sourceSha':source_sha,'stackId':stack_id,
        'changeSetArn':change_set_arn,'createdAt':created_at,'expiresAt':created_at+86400,
        'baselineSha256':sha(baseline),'originalTemplateSha256':sha(original),
        'processedTemplateSha256':sha(processed),'parametersSha256':sha(parameters),
        'permissionSha256':sha(permissions),'identitySha256':sha(identity),
        'sourcePackageSha256':sha(source_package),'packageManifest':deepcopy(packages),
        'changes':safe_inventory(changes),'nativeInventorySha256':sha(sorted(changes,key=canonical)),
        'recoveryCoordinates':deepcopy(recovery)}
    record['digest']=sha(record)
    return record

def verify_review_record(record,*,approved_digest,now,service,source_sha):
    require(isinstance(record,dict) and set(record)==FIELDS)
    require(type(record['schemaVersion']) is int and record['schemaVersion']==1)
    require(record['contract']==CONTRACT and record['environment']=='production')
    require(service in SERVICES and record['service']==service and record['purpose'] in PURPOSES)
    require(_sha(source_sha,40) and record['sourceSha']==source_sha)
    require(_sha(approved_digest) and record['digest']==approved_digest)
    require(sha({key:value for key,value in record.items() if key!='digest'})==approved_digest,
        'production_review_digest_mismatch')
    require(type(now) is int and type(record['createdAt']) is int and
        record['createdAt']<=now<record['expiresAt'] and record['expiresAt']-record['createdAt']==86400,
        'production_review_expired')
    for name in ('baselineSha256','originalTemplateSha256','processedTemplateSha256',
            'parametersSha256','permissionSha256','identitySha256','sourcePackageSha256','nativeInventorySha256'):
        require(_sha(record[name]))
    require(isinstance(record['packageManifest'],list) and isinstance(record['changes'],list)
        and isinstance(record['recoveryCoordinates'],list))
    for package in record['packageManifest']+record['recoveryCoordinates']:
        require(isinstance(package,dict) and set(package)=={'bucket','key','versionId','sha256'})
        require(all(isinstance(package[key],str) and package[key] for key in ('bucket','key','versionId'))
            and package['versionId']!='null' and _sha(package['sha256']))
    prefix=f'arn:aws:cloudformation:{REGION}:{ACCOUNT}:'
    require(record['stackId'].startswith(prefix+'stack/'))
    require(record['changeSetArn'].startswith(prefix+f'changeSet/thn-production-{service}-'))
    return deepcopy(record)

def review_inventory(changes,old,new,*,scope):
    require(scope in PURPOSES and isinstance(changes,list))
    previous=old.get('Resources',{});candidate=new.get('Resources',{})
    if scope=='registry-reader-patch':
        require(canonical(registry_reader_candidate_template(old))==canonical(new) and
                len(changes)==1 and isinstance(changes[0],dict) and
                changes[0].get('Type')=='Resource',
                'production_registry_reader_template_or_inventory_changed')
        change=changes[0].get('ResourceChange',{})
        details=change.get('Details')
        require(change.get('Action')=='Modify' and
                change.get('LogicalResourceId')==REGISTRY_READER_TABLE and
                change.get('PhysicalResourceId')==REGISTRY_READER_TABLE_NAME and
                change.get('ResourceType')=='AWS::DynamoDB::Table' and
                change.get('Replacement')=='False' and
                change.get('Scope')==['Properties'] and
                isinstance(details,list) and details and
                all(isinstance(item,dict) and
                    item.get('Target',{}).get('Attribute')=='Properties' and
                    item['Target'].get('Name')=='ResourcePolicy' and
                    item['Target'].get('RequiresRecreation','Never')=='Never'
                    and item.get('ChangeSource')=='DirectModification'
                    for item in details),
                'production_registry_reader_inventory_invalid')
        return deepcopy(changes)
    if scope=='operator-patch':
        require(canonical(operator_candidate_template(old))==canonical(new) and
                len(changes)==len(OPERATOR_RESOURCES),
                'production_operator_template_or_inventory_changed')
        seen=set()
        for item in changes:
            require(isinstance(item,dict) and item.get('Type')=='Resource',
                    'production_operator_inventory_invalid')
            change=item.get('ResourceChange',{})
            logical=change.get('LogicalResourceId')
            require(logical in OPERATOR_RESOURCES and logical not in seen and
                    change.get('Action')=='Add' and
                    change.get('ResourceType')==OPERATOR_RESOURCES[logical] and
                    change.get('Replacement') in (None,'False') and
                    not change.get('PhysicalResourceId') and
                    not change.get('Scope') and not change.get('Details') and
                    candidate.get(logical,{}).get('Type')==OPERATOR_RESOURCES[logical] and
                    candidate[logical].get('Condition')=='HasServiceBindingRegistryOperatorRole',
                    'production_operator_inventory_invalid')
            seen.add(logical)
        require(seen==set(OPERATOR_RESOURCES),'production_operator_inventory_invalid')
        return sorted(deepcopy(changes),key=canonical)
    seen=set()
    for item in changes:
        resource=item.get('ResourceChange',{})
        logical=resource.get('LogicalResourceId');kind=resource.get('ResourceType')
        action=resource.get('Action');replacement=resource.get('Replacement','False')
        if action=='Add' and replacement is None:
            replacement='False'  # CloudFormation has no prior identity to replace.
        require(isinstance(logical,str) and logical not in seen and kind in RESOURCE_TYPES)
        seen.add(logical)
        if action=='Remove':
            # SAM versions may leave the active alias; the immutable version stays retained.
            require(kind=='AWS::Lambda::Version' and previous.get(logical,{}).get('DeletionPolicy')=='Retain',
                'production_resource_deletion_blocked')
            continue
        require(action in {'Add','Modify'} and logical in candidate)
        target=candidate[logical]
        require(target.get('Type')==kind)
        if replacement!='False':
            require(replacement=='Conditional' and kind in DEPENDENCIES and
                previous.get(logical,{}).get('Properties')==target.get('Properties'),
                'production_identity_replacement_blocked')
        if scope in {'state','activate'}:
            require(logical.startswith(('Thn','ServiceBinding')) or
                (kind=='AWS::ApiGatewayV2::Api' and logical=='ContentHubApi') or
                (kind=='AWS::ApiGatewayV2::Stage' and logical=='ContentHubApiprodStage' and
                 target.get('Properties',{}).get('ApiId')=={'Ref':'ContentHubApi'} and
                 target.get('Properties',{}).get('StageName')=='prod'),
                'production_general_change_requires_own_review')
        if action=='Add' and kind in {'AWS::DynamoDB::Table','AWS::S3::Bucket',
                'AWS::Cognito::UserPool','AWS::Cognito::UserPoolClient','AWS::Logs::LogGroup'}:
            require(target.get('DeletionPolicy')=='Retain' and target.get('UpdateReplacePolicy')=='Retain',
                'production_state_retention_missing')
            props=target.get('Properties',{})
            if kind=='AWS::DynamoDB::Table':
                require(props.get('DeletionProtectionEnabled') is True and
                    props.get('PointInTimeRecoverySpecification',{}).get('PointInTimeRecoveryEnabled') is True)
            elif kind=='AWS::Cognito::UserPool':
                require(props.get('DeletionProtection')=='ACTIVE' and props.get('MfaConfiguration')=='ON')
            elif kind=='AWS::S3::Bucket':
                require(props.get('VersioningConfiguration',{}).get('Status')=='Enabled' and
                    all(props.get('PublicAccessBlockConfiguration',{}).get(k) is True for k in
                        ('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets')))
    return sorted(deepcopy(changes),key=canonical)

def select_parameters(definitions,current,overrides,*,purpose):
    require(purpose in PURPOSES and isinstance(overrides,dict) and not(set(overrides)-set(definitions)))
    previous={item['ParameterKey']:item for item in current}
    if purpose=='registry-reader-patch':
        require(not overrides and set(previous)==set(definitions),
                'production_registry_reader_parameters_changed')
    if purpose=='operator-patch':
        require(set(overrides)==set(OPERATOR_PARAMETERS) and overrides==OPERATOR_PARAMETERS and
                set(previous)==set(definitions) and
                previous['ProvisionThnProductionRegistryOperator'].get('ParameterValue')=='false' and
                previous['ThnProductionRegistryHumanPrincipalArn'].get('ParameterValue')=='BLOCKED' and
                previous['ProvisionThnServiceBindingRegistryV2State'].get('ParameterValue')=='true' and
                previous['ProvisionThnContentHubV2State'].get('ParameterValue')=='true' and
                previous['EnableThnContentHubV2'].get('ParameterValue')=='false' and
                previous['ThnProductionDependencyGate'].get('ParameterValue')=='BLOCKED',
                'production_operator_parameter_selection_invalid')
    parameters=[]
    for name,definition in definitions.items():
        if name in overrides:
            value=overrides[name]
            require(isinstance(value,str) and value and value!='****')
            if name=='EnvironmentName': require(value=='prod')
            # A production input cannot select another environment's fixed identity.
            require(not any(marker in value for marker in ('admin-test.','thn-journal-test-v2',
                'zoolanding-auth-admin-test','zoolanding-content-hub-test','zoolanding-image-upload-test')))
            parameters.append({'ParameterKey':name,'ParameterValue':value})
        elif name in previous:
            parameters.append({'ParameterKey':name,'UsePreviousValue':True})
        elif 'Default' in definition:
            parameters.append({'ParameterKey':name,'ParameterValue':str(definition['Default'])})
        else:
            raise ReleaseError('production_parameter_unavailable')
    values={p['ParameterKey']:p.get('ParameterValue',previous.get(p['ParameterKey'],{}).get('ParameterValue')) for p in parameters}
    if purpose=='general':
        require(all(values[name]==previous.get(name,{}).get('ParameterValue','false')
            for name in values if name.startswith(('EnableThn','ProvisionThn'))),
            'production_general_must_preserve_private_lifecycle')
    if purpose=='state':
        require(all(value=='false' for name,value in values.items() if name.startswith('EnableThn')),
            'production_routes_must_remain_closed')
    if purpose=='state':
        require(any(value=='true' for name,value in values.items() if name.startswith('ProvisionThn')),
            'production_state_selection_missing')
    return parameters

def seal_object(s3,bucket,key,body):
    """Private versioned object only; never accept a null/unversioned recovery coordinate."""
    require(s3.get_bucket_versioning(Bucket=bucket).get('Status')=='Enabled')
    block=s3.get_public_access_block(Bucket=bucket)['PublicAccessBlockConfiguration']
    require(all(block.get(k) is True for k in ('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets')))
    response=s3.put_object(Bucket=bucket,Key=key,Body=body,ServerSideEncryption='AES256',
        ChecksumSHA256=__import__('base64').b64encode(hashlib.sha256(body).digest()).decode(),IfNoneMatch='*')
    coordinate={'bucket':bucket,'key':key,'versionId':response.get('VersionId'),'sha256':sha(body)}
    verify_object(s3,coordinate)
    return coordinate

def verify_object(s3,coordinate):
    require(coordinate.get('versionId') not in {None,'','null'})
    response=s3.get_object(Bucket=coordinate['bucket'],Key=coordinate['key'],VersionId=coordinate['versionId'])
    body=response['Body'].read()
    require(sha(body)==coordinate['sha256'],'production_object_bytes_changed')
    return body

def snapshot(cf,stack_name):
    """Fingerprint input captured by the caller; never print or publish raw parameter values."""
    stack=cf.describe_stacks(StackName=stack_name)['Stacks'][0]
    require(stack.get('StackStatus') in {'CREATE_COMPLETE','UPDATE_COMPLETE','UPDATE_ROLLBACK_COMPLETE','IMPORT_COMPLETE','REVIEW_IN_PROGRESS'})
    resources=[];token=None
    while True:
        kwargs={'StackName':stack_name}
        if token: kwargs['NextToken']=token
        page=cf.list_stack_resources(**kwargs);resources.extend(page['StackResourceSummaries'])
        token=page.get('NextToken')
        if not token: break
    clean=lambda value:{k:v for k,v in value.items() if k not in {'ResponseMetadata','LastUpdatedTimestamp','LastUpdatedTime','CreationTime'}}
    return {'stackId':stack['StackId'],'status':stack['StackStatus'],
        'terminationProtection':stack.get('EnableTerminationProtection'),'roleArn':stack.get('RoleARN'),
        'tags':sorted(stack.get('Tags',[]),key=lambda value:value['Key']),
        'parameters':sorted(stack.get('Parameters',[]),key=lambda p:p['ParameterKey']),
        'outputs':sorted(stack.get('Outputs',[]),key=lambda p:p['OutputKey']),
        'resources':sorted((clean(r) for r in resources),key=lambda r:r['LogicalResourceId']),
        'original':cf.get_template(StackName=stack_name,TemplateStage='Original')['TemplateBody'],
        'processed':cf.get_template(StackName=stack_name,TemplateStage='Processed')['TemplateBody']}

def describe_preview(cf,arn):
    result={};changes=[];token=None
    while True:
        kwargs={'ChangeSetName':arn,'IncludePropertyValues':True}
        if token: kwargs['NextToken']=token
        page=cf.describe_change_set(**kwargs);changes.extend(page.get('Changes',[]))
        if not result: result={k:v for k,v in page.items() if k not in {'Changes','NextToken','ResponseMetadata'}}
        token=page.get('NextToken')
        if not token: break
    result['Changes']=changes
    require(result.get('Status')=='CREATE_COMPLETE' and result.get('ExecutionStatus')=='AVAILABLE',
        'production_preview_unavailable')
    return result

def parse_template(value):
    if isinstance(value,dict): return value
    import yaml
    return yaml.safe_load(value)

def execute_retained(cf,s3,record,*,approved_digest,source_sha,service,baseline,
        permissions,identity,source_package,authority_check,now=None):
    now=int(time.time()) if now is None else now
    verify_review_record(record,approved_digest=approved_digest,now=now,service=service,source_sha=source_sha)
    require(sha(baseline)==record['baselineSha256'],'production_baseline_changed')
    require(sha(permissions)==record['permissionSha256'] and sha(identity)==record['identitySha256'],
        'production_permissions_changed')
    require(sha(source_package)==record['sourcePackageSha256'],'production_source_package_changed')
    for coordinate in record['packageManifest']+record['recoveryCoordinates']: verify_object(s3,coordinate)
    preview=describe_preview(cf,record['changeSetArn'])
    require(preview['StackId']==record['stackId'])
    require(safe_inventory(preview['Changes'])==record['changes'] and
        sha(sorted(preview['Changes'],key=canonical))==record['nativeInventorySha256'],
        'production_native_inventory_changed')
    original=parse_template(cf.get_template(ChangeSetName=record['changeSetArn'],TemplateStage='Original')['TemplateBody'])
    processed=parse_template(cf.get_template(ChangeSetName=record['changeSetArn'],TemplateStage='Processed')['TemplateBody'])
    require(sha(original)==record['originalTemplateSha256'] and sha(processed)==record['processedTemplateSha256'])
    require(sha(preview.get('Parameters',[]))==record['parametersSha256'])
    review_inventory(preview['Changes'],parse_template(baseline['processed']),processed,scope=record['purpose'])
    # This is the only execution mutation. No package/build/create-change-set call exists here.
    require(callable(authority_check),'production_fresh_source_authority_missing')
    authority_check()
    cf.execute_change_set(ChangeSetName=record['changeSetArn'],StackName=record['stackId'])
    return {'executed':True,'digest':record['digest'],'changeSetArn':record['changeSetArn']}

def cleanup_retained(cf,record,*,service,source_sha):
    verify_review_record(record,approved_digest=record['digest'],now=min(int(time.time()),record['expiresAt']-1),
        service=service,source_sha=source_sha)
    preview=describe_preview(cf,record['changeSetArn'])
    require(preview['StackId']==record['stackId'] and safe_inventory(preview['Changes'])==record['changes'] and
        sha(sorted(preview['Changes'],key=canonical))==record['nativeInventorySha256'])
    cf.delete_change_set(ChangeSetName=record['changeSetArn'],StackName=record['stackId'])
