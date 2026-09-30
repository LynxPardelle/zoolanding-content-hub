"""Protected, exact four-resource IMPORT for retained production Content Hub state.

Review deletes its change set. Execute recreates it from the reviewed,
versioned template and checks every fingerprint before calling CloudFormation.
No customer data or raw policy/template is printed or transported as a review.
"""
from pathlib import Path
import argparse
import json
import os
import re
import sys
import time
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import thn_production_import as guard
from tools import thn_production_release as release
from tools.run_thn_production_release import source_selection, validate_github_trust
from tools.thn_production_service import CONFIG

SOURCE_COORDINATE = {
    'bucket': CONFIG['bucket'],
    'key': ('thn/production/hub/16b0655d3c218cf75e26eb37398fddadd40303f6/'
            '36631040845/1/candidate-original.json'),
    'versionId': 'l55.x4qn1jxUOKxUgrY0JYjkSmspBDIP',
    'sha256': '8c3ccc33310c7802820c25085ff9c16b7aa017060f28d06a653004afcf888d2b',
}
STACK = CONFIG['stack']
DEPLOY_ARN = f'arn:aws:iam::{release.ACCOUNT}:role/{CONFIG["deployRole"]}'
EXECUTION_ARN = f'arn:aws:iam::{release.ACCOUNT}:role/{CONFIG["executionRole"]}'
REGISTRY_ARN = ('arn:aws:dynamodb:us-east-1:765932874577:table/'
                'zoolanding-content-hub-prod-ServiceBindingRegistryV2')
PRIVATE_BUCKET = guard.TARGETS['ThnContentHubV2PrivateStore'][1]
PRIVATE_BUCKET_ARN = f'arn:aws:s3:::{PRIVATE_BUCKET}'
DDB_PROVIDER_READ = frozenset({
    'dynamodb:DescribeTable', 'dynamodb:DescribeContinuousBackups',
    'dynamodb:DescribeContributorInsights',
    'dynamodb:DescribeKinesisStreamingDestination',
    'dynamodb:ListTagsOfResource', 'dynamodb:GetResourcePolicy',
    'dynamodb:DescribeTimeToLive',
})
S3_PROVIDER_READ = frozenset({
    's3:GetAccelerateConfiguration', 's3:GetLifecycleConfiguration',
    's3:GetBucketPublicAccessBlock', 's3:GetAnalyticsConfiguration',
    's3:GetBucketCORS', 's3:GetEncryptionConfiguration',
    's3:GetInventoryConfiguration', 's3:GetBucketLogging',
    's3:GetMetricsConfiguration', 's3:GetBucketNotification',
    's3:GetBucketVersioning', 's3:GetReplicationConfiguration',
    's3:GetBucketWebsite', 's3:GetBucketObjectLockConfiguration',
    's3:GetBucketTagging', 's3:ListTagsForResource', 's3:GetBucketAbac',
    's3:GetBucketOwnershipControls', 's3:GetIntelligentTieringConfiguration',
    's3:GetBucketMetadataTableConfiguration', 's3:ListBucket',
})


def sealed_source(source_sha):
    source = source_selection(source_sha)
    source['importFiles'] = {name: release.sha((ROOT / name).read_bytes()) for name in (
        'tools/thn_production_import.py', 'tools/run_thn_production_import.py',
        '.github/workflows/import-thn-production-retained.yml',
        'requirements-import.txt')}
    return source


def require_caller(session):
    identity = session.client('sts').get_caller_identity()
    guard.require(session.region_name == release.REGION and
                  identity.get('Account') == release.ACCOUNT and
                  str(identity.get('Arn', '')).startswith(
                      f'arn:aws:sts::{release.ACCOUNT}:assumed-role/{CONFIG["deployRole"]}/')
                  and os.environ.get('AWS_ROLE_ARN') == DEPLOY_ARN,
                  'production_import_caller_invalid')


def snapshot(session):
    baseline = release.snapshot(session.client('cloudformation'), STACK)
    baseline['original'] = release.parse_template(baseline['original'])
    baseline['processed'] = release.parse_template(baseline['processed'])
    return guard.validate_stack_baseline(baseline)


def pinned_candidate(session):
    body = release.verify_object(session.client('s3'), SOURCE_COORDINATE)
    candidate = release.parse_template(body.decode('utf-8'))
    guard.require(isinstance(candidate, dict) and
                  candidate.get('Transform') == 'AWS::Serverless-2016-10-31',
                  'production_import_source_invalid')
    return candidate


def read_targets(session, import_template):
    dynamodb = session.client('dynamodb')
    tables = {}
    for logical, (kind, name) in guard.TARGETS.items():
        if kind != 'AWS::DynamoDB::Table':
            continue
        table = dynamodb.describe_table(TableName=name)['Table']
        pitr = dynamodb.describe_continuous_backups(TableName=name)[
            'ContinuousBackupsDescription']['PointInTimeRecoveryDescription']
        tables[logical] = {'Table': {
            key: table.get(key) for key in ('TableName', 'TableStatus', 'TableArn',
                'TableId', 'AttributeDefinitions', 'KeySchema',
                'DeletionProtectionEnabled')},
            'PointInTimeRecoveryDescription': {
                'PointInTimeRecoveryStatus': pitr.get('PointInTimeRecoveryStatus'),
                'RecoveryPeriodInDays': pitr.get('RecoveryPeriodInDays')}}
        tables[logical]['Table']['BillingModeSummary'] = {
            'BillingMode': table.get('BillingModeSummary', {}).get('BillingMode')}
        tables[logical]['Table']['SSEDescription'] = {
            key: table.get('SSEDescription', {}).get(key) for key in
            ('Status', 'SSEType', 'KMSMasterKeyArn')}
    s3 = session.client('s3')
    s3.head_bucket(Bucket=PRIVATE_BUCKET, ExpectedBucketOwner=release.ACCOUNT)
    bucket = {
        'Versioning': s3.get_bucket_versioning(Bucket=PRIVATE_BUCKET),
        'Encryption': s3.get_bucket_encryption(Bucket=PRIVATE_BUCKET),
        'PublicAccessBlock': s3.get_public_access_block(Bucket=PRIVATE_BUCKET)[
            'PublicAccessBlockConfiguration'],
    }
    for result in (bucket['Versioning'], bucket['Encryption']):
        result.pop('ResponseMetadata', None)
    registry = dynamodb.get_resource_policy(ResourceArn=REGISTRY_ARN)
    policy = json.loads(registry['Policy'])
    guard.require(isinstance(policy, dict) and isinstance(policy.get('Statement'), list)
                  and re.fullmatch(r'[0-9]+', registry.get('RevisionId', '')),
                  'production_import_registry_policy_invalid')
    identities = guard.validate_live_resource_settings(import_template, tables, bucket)
    return {'identities': identities, 'tables': tables, 'bucket': bucket,
            'policyRevision': registry['RevisionId'], 'policySha256': release.sha(policy)}


def _allowed(iam, role, actions, resource):
    response = iam.simulate_principal_policy(
        PolicySourceArn=role, ActionNames=actions, ResourceArns=[resource])
    results = response.get('EvaluationResults', [])
    guard.require(response.get('IsTruncated') is not True and
                  len(results) == len(actions) and
                  {r.get('EvalActionName', '').lower() for r in results} ==
                  {action.lower() for action in actions} and
                  all(r.get('EvalDecision') == 'allowed' and
                      not r.get('MissingContextValues') and
                      r.get('EvalResourceName') == resource for r in results),
                  'production_import_permission_denied')
    return sorted(({'action': r['EvalActionName'].lower(), 'resource': resource,
                    'decision': r['EvalDecision']} for r in results),
                  key=lambda row: row['action'])


def effective_permissions(session, run_id, source_sha):
    iam = session.client('iam')
    cf = session.client('cloudformation')
    proof = []
    deploy_role = iam.get_role(RoleName=CONFIG['deployRole'])['Role']
    execute_role = iam.get_role(RoleName=CONFIG['executionRole'])['Role']
    validate_github_trust(deploy_role['AssumeRolePolicyDocument'])
    guard.require(deploy_role['Arn'] == DEPLOY_ARN and
                  execute_role['Arn'] == EXECUTION_ARN and
                  not deploy_role.get('PermissionsBoundary') and
                  not execute_role.get('PermissionsBoundary') and
                  execute_role['AssumeRolePolicyDocument']['Statement'] == [{
                      'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                      'Principal': {'Service': 'cloudformation.amazonaws.com'}}],
                  'production_import_role_changed')
    proof.append({'roleIds': [deploy_role['RoleId'], execute_role['RoleId']],
                  'trustSha256': [release.sha(deploy_role['AssumeRolePolicyDocument']),
                                  release.sha(execute_role['AssumeRolePolicyDocument'])]})
    inline = iam.get_role_policy(RoleName=CONFIG['deployRole'],
                                 PolicyName='ThnProductionHubImportPreflightRead')
    expected_policy = {'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Action': ['dynamodb:GetResourcePolicy'],
         'Resource': REGISTRY_ARN},
        {'Effect': 'Allow', 'Action': ['s3:GetBucketVersioning',
                                     's3:GetEncryptionConfiguration',
                                     's3:GetBucketPublicAccessBlock', 's3:ListBucket'],
         'Resource': PRIVATE_BUCKET_ARN}]}
    guard.require(inline.get('PolicyDocument') == expected_policy,
                  'production_import_read_policy_changed')
    proof.append({'importReadPolicySha256': release.sha(inline['PolicyDocument'])})
    for kind, expected in [('AWS::DynamoDB::Table', DDB_PROVIDER_READ),
                           ('AWS::S3::Bucket', S3_PROVIDER_READ)]:
        schema = json.loads(cf.describe_type(Type='RESOURCE', TypeName=kind)['Schema'])
        guard.require(set(schema.get('handlers', {}).get('read', {}).get('permissions', [])) ==
                      expected, 'production_import_provider_permissions_changed')
        proof.append({'type': kind, 'schemaSha256': release.sha(schema)})
    proof += _allowed(iam, DEPLOY_ARN,
                      ['dynamodb:DescribeTable', 'dynamodb:DescribeContinuousBackups',
                       'dynamodb:GetResourcePolicy'], REGISTRY_ARN)
    proof += _allowed(iam, DEPLOY_ARN,
                      ['s3:GetBucketVersioning', 's3:GetEncryptionConfiguration',
                       's3:GetBucketPublicAccessBlock', 's3:ListBucket'], PRIVATE_BUCKET_ARN)
    for logical, (kind, name) in guard.TARGETS.items():
        if kind == 'AWS::DynamoDB::Table':
            proof += _allowed(iam, EXECUTION_ARN,
                              sorted(DDB_PROVIDER_READ),
                              f'arn:aws:dynamodb:{release.REGION}:{release.ACCOUNT}:table/{name}')
    proof += _allowed(iam, EXECUTION_ARN,
                      sorted(S3_PROVIDER_READ), PRIVATE_BUCKET_ARN)
    stack_arn = f'arn:aws:cloudformation:{release.REGION}:{release.ACCOUNT}:stack/{STACK}/*'
    proof += _allowed(iam, DEPLOY_ARN,
                      ['cloudformation:CreateChangeSet', 'cloudformation:DescribeChangeSet',
                       'cloudformation:DeleteChangeSet', 'cloudformation:ExecuteChangeSet',
                       'cloudformation:GetTemplate', 'cloudformation:DescribeStacks',
                       'cloudformation:ListStackResources'], stack_arn)
    proof += _allowed(iam, DEPLOY_ARN, ['s3:GetObject', 's3:GetObjectVersion'],
                      f'arn:aws:s3:::{SOURCE_COORDINATE["bucket"]}/{SOURCE_COORDINATE["key"]}')
    guard.require(bool(re.fullmatch(r'[1-9][0-9]*/[1-9][0-9]*', run_id)))
    guard.require(bool(re.fullmatch('[a-f0-9]{40}', source_sha)),
                  'production_import_source_invalid')
    # Use a fixed representative key so review/execute permission hashes match.
    template_key = f'thn/production/hub/import/{source_sha}/1/1/import-original.json'
    proof += _allowed(iam, DEPLOY_ARN,
                      ['s3:PutObject', 's3:GetObject', 's3:GetObjectVersion'],
                      f'arn:aws:s3:::{CONFIG["bucket"]}/{template_key}')
    return release.sha(proof)


def capture(session, run_id, source_sha):
    require_caller(session)
    baseline = snapshot(session)
    candidate = guard.build_import_template(baseline['original'], pinned_candidate(session))
    target = read_targets(session, candidate)
    permissions_sha = effective_permissions(session, run_id, source_sha)
    body = release.canonical(candidate)
    return {'baseline': baseline, 'candidate': candidate, 'templateBytes': body,
            'target': target, 'permissionSha256': permissions_sha}


def parameters(baseline):
    return [{'ParameterKey': item['ParameterKey'], 'UsePreviousValue': True}
            for item in baseline['parameters']]


def template_url(coordinate):
    return (f'https://{coordinate["bucket"]}.s3.{release.REGION}.amazonaws.com/'
            f'{quote(coordinate["key"])}?versionId={quote(coordinate["versionId"])}')


def import_identifiers():
    return [{'ResourceType': kind, 'LogicalResourceId': logical,
             'ResourceIdentifier': {('TableName' if kind == 'AWS::DynamoDB::Table'
                                     else 'BucketName'): name}}
            for logical, (kind, name) in guard.TARGETS.items()]


def create_preview(session, captured, coordinate, run_id, phase):
    cf = session.client('cloudformation')
    name = f'thn-production-hub-import-{phase}-{run_id.replace("/", "-")}'
    response = cf.create_change_set(
        StackName=captured['baseline']['stackId'], ChangeSetName=name,
        ChangeSetType='IMPORT', TemplateURL=template_url(coordinate),
        ResourcesToImport=import_identifiers(), Parameters=parameters(captured['baseline']),
        Capabilities=['CAPABILITY_AUTO_EXPAND', 'CAPABILITY_NAMED_IAM'],
        RoleARN=EXECUTION_ARN, Tags=captured['baseline'].get('tags', []))
    arn = response['Id']
    cf.get_waiter('change_set_create_complete').wait(ChangeSetName=arn,
                                                       WaiterConfig={'Delay': 5, 'MaxAttempts': 120})
    preview = release.describe_preview(cf, arn)
    # DescribeChangeSet omits ChangeSetType even for a successful IMPORT request.
    # The exact four Import actions are checked by validate_import_inventory below.
    guard.require(preview.get('StackId') == captured['baseline']['stackId'] and
                  preview.get('ChangeSetType') in (None, 'IMPORT') and
                  preview.get('Parameters') in (None,
                                                captured['baseline']['parameters']),
                  'production_import_preview_baseline_changed')
    changes = guard.validate_import_inventory(preview['Changes'])
    original = release.parse_template(cf.get_template(
        ChangeSetName=arn, TemplateStage='Original')['TemplateBody'])
    processed = release.parse_template(cf.get_template(
        ChangeSetName=arn, TemplateStage='Processed')['TemplateBody'])
    guard.require(original == captured['candidate'] and
                  set(processed.get('Resources', {})) ==
                  set(captured['baseline']['processed']['Resources']) | set(guard.TARGETS)
                  and all(processed['Resources'][key] == value for key, value in
                          captured['baseline']['processed']['Resources'].items()),
                  'production_import_processed_template_changed')
    return arn, changes, release.sha(sorted(preview['Changes'], key=release.canonical))


def review(session, captured, source_sha, run_id, output_path):
    coordinate = release.seal_object(
        session.client('s3'), CONFIG['bucket'],
        f'thn/production/hub/import/{source_sha}/{run_id}/import-original.json',
        captured['templateBytes'])
    arn, changes, native_sha = create_preview(session, captured, coordinate, run_id,
                                               'review')
    record = guard.make_import_review_record(
        source_sha=source_sha, stack_id=captured['baseline']['stackId'],
        baseline_sha=release.sha(captured['baseline']),
        target_sha=release.sha(captured['target']),
        template_sha=release.sha(captured['templateBytes']),
        template_coordinate=coordinate,
        registry_policy_revision=captured['target']['policyRevision'],
        registry_policy_sha=captured['target']['policySha256'],
        permission_sha=captured['permissionSha256'], native_inventory_sha=native_sha,
        changes=[
            {'Type': 'Resource', 'ResourceChange': change} for change in changes],
        created_at=int(time.time()))
    Path(output_path).write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    session.client('cloudformation').delete_change_set(ChangeSetName=arn)
    print(json.dumps({'digest': record['digest'], 'changes': record['changes'],
                      'expiresAt': record['expiresAt']}))


def execute(session, captured, source_sha, run_id, record_path, approved_digest):
    record = json.loads(Path(record_path).read_text())
    guard.verify_import_review_record(
        record, approved_digest=approved_digest, source_sha=source_sha,
        stack_id=captured['baseline']['stackId'], now=int(time.time()))
    guard.require(record['baselineSha256'] == release.sha(captured['baseline'])
                  and record['targetSha256'] == release.sha(captured['target'])
                  and record['permissionSha256'] == captured['permissionSha256']
                  and record['registryPolicyRevision'] == captured['target']['policyRevision']
                  and record['registryPolicySha256'] == captured['target']['policySha256']
                  and record['templateSha256'] == release.sha(captured['templateBytes']),
                  'production_import_review_state_changed')
    body = release.verify_object(session.client('s3'), record['templateCoordinate'])
    guard.require(body == captured['templateBytes'], 'production_import_sealed_template_changed')
    arn, changes, native_sha = create_preview(
        session, captured, record['templateCoordinate'], run_id, 'execute')
    guard.require(changes == record['changes'] and
                  native_sha == record['nativeInventorySha256'],
                  'production_import_inventory_changed')
    # Repeat all read-only proofs immediately before the irreversible import.
    fresh = capture(session, run_id, source_sha)
    guard.require(release.sha(fresh['baseline']) == record['baselineSha256']
                  and release.sha(fresh['target']) == record['targetSha256']
                  and fresh['target']['policyRevision'] == record['registryPolicyRevision']
                  and fresh['target']['policySha256'] == record['registryPolicySha256']
                  and fresh['permissionSha256'] == record['permissionSha256']
                  and fresh['templateBytes'] == body,
                  'production_import_preexecute_state_changed')
    sealed_source(source_sha)
    session.client('cloudformation').execute_change_set(
        ChangeSetName=arn, ClientRequestToken=f'thn-hub-import-{record["digest"]}')
    cf = session.client('cloudformation')
    for _ in range(120):
        stack = cf.describe_stacks(StackName=record['stackId'])['Stacks'][0]
        if stack['StackStatus'] == 'IMPORT_COMPLETE':
            break
        guard.require(stack['StackStatus'] in ('IMPORT_IN_PROGRESS',
                      'IMPORT_COMPLETE_CLEANUP_IN_PROGRESS'),
                      'production_import_execution_failed')
        time.sleep(5)
    else:
        raise guard.ImportError('production_import_execution_timeout')
    resources = []
    for page in cf.get_paginator('list_stack_resources').paginate(StackName=record['stackId']):
        resources.extend(page['StackResourceSummaries'])
    before = {item['LogicalResourceId']: item['PhysicalResourceId'] for item in
              captured['baseline']['resources']}
    after = {item['LogicalResourceId']: item['PhysicalResourceId'] for item in resources}
    guard.require(len(resources) == 21 and len(after) == 21 and
                  all(after.get(key) == value for key, value in before.items()) and
                  all(after.get(key) == name for key, (_, name) in guard.TARGETS.items()),
                  'production_import_post_identity_mismatch')
    current = read_targets(session, captured['candidate'])
    guard.require(current['policyRevision'] == record['registryPolicyRevision'] and
                  current['policySha256'] == record['registryPolicySha256'] and
                  release.sha(current) == record['targetSha256'],
                  'production_import_post_target_mismatch')
    print(json.dumps({'importComplete': True, 'digest': record['digest'],
                      'resources': len(resources), 'driftCheck': 'requires administrator read'}))


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=('validate', 'preflight', 'review', 'execute'))
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--record', default='production-import-review.json')
    parser.add_argument('--approved-digest', default='')
    args = parser.parse_args(argv)
    try:
        source = sealed_source(args.source_sha)
        guard.require(not args.approved_digest or bool(re.fullmatch('[a-f0-9]{64}',
                                                            args.approved_digest)))
        if args.operation == 'validate':
            return 0
        import boto3
        session = boto3.Session(region_name=release.REGION)
        run_id = f'{os.environ["GITHUB_RUN_ID"]}/{os.environ["GITHUB_RUN_ATTEMPT"]}'
        captured = capture(session, run_id, args.source_sha)
        guard.require(sealed_source(args.source_sha) == source,
                      'production_import_source_changed')
        if args.operation == 'preflight':
            print(json.dumps({'ready': True, 'baselineSha256': release.sha(captured['baseline']),
                              'templateSha256': release.sha(captured['templateBytes'])}))
        elif args.operation == 'review':
            review(session, captured, args.source_sha, run_id, args.record)
        else:
            guard.require(bool(args.approved_digest), 'production_import_approval_missing')
            execute(session, captured, args.source_sha, run_id, args.record,
                    args.approved_digest)
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, guard.ImportError) else type(error).__name__
        print('production_import_failed:' + code +
              '; retain evidence and diagnose before another run', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
