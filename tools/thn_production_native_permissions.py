"""Conditional native handler permission projection for the supported candidate.

Inputs are the live provider schema and processed templates, never a guessed
universal policy. Unsupported KMS/network/import/metadata services stop review.
The selected read/mutation/rollback actions remain a subset of that schema.
"""
from tools.thn_production_release import require, stable_simulation_evaluations

def selected_actions(kind,handlers,changes,template,previous=None):
    actions=set();old=(previous or {}).get('Resources',{});new=template.get('Resources',{})
    for change in changes:
        logical=change['LogicalResourceId'];operation={'Add':'create','Modify':'update','Remove':'delete'}.get(change['Action'])
        require(operation in handlers,'production_native_handler_unavailable')
        before=old.get(logical,{}).get('Properties',{});after=new.get(logical,{}).get('Properties',{})
        require(after or before,'production_native_resource_properties_missing')
        fields={**before,**after}
        required=set(handlers.get('read',{}).get('permissions',[]))|set(handlers[operation].get('permissions',[]))
        if operation=='create':required.update(handlers.get('delete',{}).get('permissions',[]))
        if kind=='AWS::Lambda::Function':
            require(not any(fields.get(k) for k in ('KmsKeyArn','SourceKMSKeyArn','VpcConfig','FileSystemConfigs','CodeSigningConfigArn','CapacityProviderConfig','Layers')), 'production_native_lambda_feature_not_reviewed')
            required={a for a in required if not a.startswith(('kms:','ec2:','elasticfilesystem:','s3files:')) and a not in {'lambda:PassCapacityProvider','lambda:GetLayerVersion','lambda:GetCodeSigningConfig','lambda:PutFunctionCodeSigningConfig','lambda:DeleteFunctionCodeSigningConfig'}}
        elif kind=='AWS::Lambda::Alias':
            require(not new.get(logical,{}).get('UpdatePolicy') and not old.get(logical,{}).get('UpdatePolicy'),'production_native_alias_deployment_preference_not_reviewed')
            required={a for a in required if a.startswith('lambda:')}
        elif kind.startswith('AWS::SNS'):
            require(not any(fields.get(k) for k in ('SubscriptionRoleArn','DeliveryStatusLogging','KmsMasterKeyId')),'production_native_topic_feature_not_reviewed')
            required={a for a in required if a.startswith('sns:')}
        elif kind=='AWS::DynamoDB::Table':
            require(not any(fields.get(k) for k in ('ImportSourceSpecification','KinesisStreamSpecification','ContributorInsightsSpecification','GlobalTableSettings','Replicas')) and not fields.get('SSESpecification',{}).get('KMSMasterKeyId'),'production_native_table_feature_not_reviewed')
            excluded={'BatchWriteItem','DeleteItem','GetItem','PutItem','Query','Scan','UpdateItem','AssociateTableReplica','CreateTableReplica','ImportTable','DescribeImport','DisableKinesisStreamingDestination','EnableKinesisStreamingDestination','UpdateKinesisStreamingDestination','UpdateContributorInsights'}
            required={a for a in required if a.startswith('dynamodb:') and a.split(':')[1] not in excluded}
        elif kind=='AWS::IAM::Policy':
            require(fields.get('Roles') and not fields.get('Users') and not fields.get('Groups'),'production_native_policy_scope_not_reviewed')
            required={a for a in required if 'UserPolicy' not in a and 'GroupPolicy' not in a}
        elif kind=='AWS::IAM::Role':
            require(not fields.get('PermissionsBoundary'),'production_native_boundary_not_reviewed')
            required-={'iam:PutRolePermissionsBoundary','iam:DeleteRolePermissionsBoundary'}
            if not fields.get('ManagedPolicyArns'):required-={'iam:AttachRolePolicy','iam:DetachRolePolicy'}
        elif kind=='AWS::S3::Bucket':
            require(not any(fields.get(k) for k in ('MetadataConfiguration','MetadataTableConfiguration','ReplicationConfiguration','ObjectLockConfiguration','ObjectLockEnabled','AnalyticsConfigurations','InventoryConfigurations','IntelligentTieringConfigurations','MetricsConfigurations','AccelerateConfiguration','AccessControl','AbacStatus')),'production_native_bucket_feature_not_reviewed')
            require(all(item.get('ServerSideEncryptionByDefault',{}).get('SSEAlgorithm')=='AES256' for item in fields.get('BucketEncryption',{}).get('ServerSideEncryptionConfiguration',[])),'production_native_bucket_kms_not_reviewed')
            excluded=('Metadata','Replication','ObjectLock','Analytics','Inventory','IntelligentTiering','Metrics','Accelerate','ObjectAcl','BucketAcl','Abac')
            required={a for a in required if a.startswith('s3:') and not(any(marker in a.split(':')[1] for marker in excluded) and not a.startswith('s3:Get')) and a!='s3:DeleteObject'}
        elif kind=='AWS::Logs::LogGroup':
            # Check both templates: clearing an unsupported feature still needs
            # its removal permissions and must not bypass this closed profile.
            features=('KmsKeyId','DataProtectionPolicy','FieldIndexPolicies',
                'DeliveryDestinationConfiguration','ResourcePolicyDocument',
                'BearerTokenAuthenticationEnabled','DeletionProtectionEnabled')
            require(not any(p.get(k) for p in (before,after) for k in features)
                and all(p.get('LogGroupClass')!='DELIVERY' for p in (before,after)),
                'production_native_log_feature_not_reviewed')
            conditional={'logs:AssociateKmsKey','logs:DisassociateKmsKey',
                'logs:PutDataProtectionPolicy','logs:CreateLogDelivery',
                'logs:PutIndexPolicy','logs:DeleteIndexPolicy',
                'logs:PutResourcePolicy','logs:DeleteResourcePolicy',
                'logs:PutBearerTokenAuthentication','logs:PutLogGroupDeletionProtection'}
            required={a for a in required if a.startswith('logs:') and a not in conditional}
        elif kind.startswith('AWS::Cognito'):
            require(not any(fields.get(k) for k in ('SmsConfiguration','UserPoolAddOns')) and not any(fields.get('LambdaConfig',{}).get(k) for k in ('KMSKeyID','CustomSMSSender','CustomEmailSender')) and fields.get('EmailConfiguration',{}).get('EmailSendingAccount','COGNITO_DEFAULT')=='COGNITO_DEFAULT','production_native_pool_feature_not_reviewed')
            required={a for a in required if a.startswith('cognito-idp:')}
        elif kind.startswith('AWS::ApiGateway'):
            require(not fields.get('BodyS3Location'),'production_native_api_external_body_not_reviewed')
            required={a for a in required if a.lower()!='s3:getobject'}
            if not fields.get('CredentialsArn'):required.discard('iam:PassRole')
        require(required and all(__import__('re').fullmatch(r'[a-z0-9-]+:[A-Za-z][A-Za-z0-9]*',a) for a in required),'production_native_handler_permissions_unavailable')
        actions.update(required)
    return actions


def prove_event_rule_resources(iam,requests,execution_arn,actions,changes,template,stack):
    """Simulate EventBridge grants against the physical names CloudFormation creates.

    A simulation against an IAM wildcard string can succeed even when that
    string cannot match a real generated rule. For unnamed rules CloudFormation
    uses 25 characters from the stack and logical IDs plus a random suffix.
    """
    proofs=[]
    for item in changes:
        change=item['ResourceChange']
        if change['ResourceType']!='AWS::Events::Rule':
            continue
        logical=change['LogicalResourceId']
        properties=template['Resources'].get(logical,{}).get('Properties',{})
        name=properties.get('Name')
        require(name is None or isinstance(name,str),'production_event_rule_name_unreviewed')
        if name is None:
            prefix=f'{stack[:25]}-{logical[:25]}-'
            pattern=f'arn:aws:events:us-east-1:765932874577:rule/{prefix}*'
            physical=prefix+'A'*12 if change['Action']=='Add' else change.get('PhysicalResourceId')
            require(isinstance(physical,str) and physical.startswith(prefix) and
                    len(physical)==len(prefix)+12,'production_event_rule_physical_name_unreviewed')
        else:
            pattern=f'arn:aws:events:us-east-1:765932874577:rule/{name}'
            physical=name if change['Action']=='Add' else change.get('PhysicalResourceId')
            require(physical==name,'production_event_rule_physical_name_unreviewed')
        concrete=f'arn:aws:events:us-east-1:765932874577:rule/{physical}'
        request=next((row for row in requests if row.get('principalArn')==execution_arn and
                      actions<=set(row.get('actions',[])) and pattern in row.get('resources',[])),None)
        require(request is not None,'production_event_rule_resource_unproven')
        result=iam.simulate_principal_policy(PolicySourceArn=execution_arn,
            ActionNames=sorted(action.lower() for action in actions),ResourceArns=[concrete],
            ContextEntries=request['context'])
        evaluations=result.get('EvaluationResults',[])
        require(result.get('IsTruncated') is not True and
                {entry['EvalActionName'].lower() for entry in evaluations}=={a.lower() for a in actions} and
                all(entry.get('EvalDecision')=='allowed' and not entry.get('MissingContextValues') and
                    (entry.get('EvalResourceName')==concrete if not entry.get('ResourceSpecificResults') else all(
                        row.get('EvalResourceName')==concrete and row.get('EvalResourceDecision')=='allowed' and
                        not row.get('MissingContextValues') for row in entry['ResourceSpecificResults']))
                    for entry in evaluations),'production_event_rule_effective_permission_denied')
        proofs.append({'concreteResource':concrete,'actions':sorted(actions),
                       'context':request['context'],
                       'evaluation':stable_simulation_evaluations(evaluations)})
    return proofs
