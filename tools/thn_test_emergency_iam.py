"""Protected, source-free TEST repair of the emergency reader's inline policy."""
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import quote

import boto3
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import thn_production_release as guard
from tools import thn_production_import as imported

ACCOUNT = guard.ACCOUNT
REGION = guard.REGION
STACK = 'zoolanding-content-hub-test'
PURPOSE = 'emergency-iam-patch'
ROLE = 'ThnContentHubV2EmergencyWithdrawRole'
ROLE_NAME = 'zlp-thn-ch-test-emergency-withdraw'
EMPTY_STATEMENT_SHA = guard.sha({})
RECORD_FIELDS = {'schemaVersion', 'sourceSha', 'stackId', 'changeSetArn',
                 'createdAt', 'expiresAt', 'baselineSha256', 'candidateSha256',
                 'originalSha256', 'processedSha256', 'parametersSha256',
                 'inventorySha256', 'registryPolicySha256', 'templateObject', 'digest'}
REGISTRY_ARN = (f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/'
                'zoolanding-content-hub-test-ServiceBindingRegistryV2')
REGISTRY_POLICY_REVISION = '1790111297817'
REGISTRY_POLICY_SHA256 = '261679d358ddbde304182d65f6be48137780c8f60a22e3b3e70b739e8bf10fa5'


def require(condition, code='test_emergency_iam_guard_failed'):
    guard.require(condition, code)


def source_template():
    return yaml.safe_load((ROOT / 'template.yaml').read_text(encoding='utf-8'))


def statement(template):
    role = template['Resources'][ROLE]
    require(role['Type'] == 'AWS::IAM::Role' and
            role['Properties']['RoleName'] == ROLE_NAME and
            len(role['Properties']['Policies']) == 1)
    matches = [item for item in role['Properties']['Policies'][0]['PolicyDocument']['Statement']
               if item.get('Sid') == 'ReadExactThnBindingBeforeWithdrawal']
    require(len(matches) <= 1)
    return matches[0] if matches else {}


def candidate(template):
    source = source_template()
    desired = statement(source)
    require(desired.get('Effect') == 'Allow' and desired.get('Action') == ['dynamodb:GetItem'] and
            desired.get('Condition') == {
                'ForAllValues:StringEquals': {
                    'dynamodb:LeadingKeys': ['SERVICE_BINDING#test#thn-journal-test-v2']},
                'Null': {'dynamodb:LeadingKeys': 'false'}})
    require(guard.sha(statement(template)) == EMPTY_STATEMENT_SHA)
    return guard.iam_patch_candidate_template(template, source, PURPOSE)


def baseline(cf):
    value = guard.snapshot(cf, STACK)
    require(value['status'] == 'UPDATE_COMPLETE' and value['terminationProtection'] is True and
            value['roleArn'] is None and len(value['resources']) == 64)
    resources = {item['LogicalResourceId']: item for item in value['resources']}
    require(resources[ROLE]['ResourceType'] == 'AWS::IAM::Role' and
            resources[ROLE]['PhysicalResourceId'] == ROLE_NAME)
    for stage in ('original', 'processed'):
        candidate(guard.parse_template(value[stage]))
    return value


def describe_preview(cf, change_set):
    """Pass the exact stack on every TEST change-set read as existing releases do."""
    first = None
    changes = []
    token = None
    while True:
        request = {'StackName': STACK, 'ChangeSetName': change_set,
                   'IncludePropertyValues': True}
        if token:
            request['NextToken'] = token
        page = cf.describe_change_set(**request)
        if first is None:
            first = {key: value for key, value in page.items()
                     if key not in ('Changes', 'NextToken', 'ResponseMetadata')}
        changes.extend(page.get('Changes', []))
        token = page.get('NextToken')
        if not token:
            break
    require(first.get('Status') == 'CREATE_COMPLETE' and
            first.get('ExecutionStatus') == 'AVAILABLE')
    first['Changes'] = changes
    return first


def registry_policy_fingerprint(session):
    response = session.client('dynamodb').get_resource_policy(ResourceArn=REGISTRY_ARN)
    # DynamoDB can reorder Principal.AWS entries under the same policy
    # revision. Hash the reviewed semantic form, not its returned list order.
    value = guard.sha(imported.normalize_registry_policy(json.loads(response['Policy'])))
    require(response.get('RevisionId') == REGISTRY_POLICY_REVISION and
            value == REGISTRY_POLICY_SHA256, 'test_emergency_registry_policy_changed')
    return value


def preview_guard(cf, change_set, before):
    preview = describe_preview(cf, change_set)
    require(preview['StackId'] == before['stackId'] and len(preview['Changes']) == 1)
    change = preview['Changes'][0]['ResourceChange']
    require(change.get('PhysicalResourceId') == ROLE_NAME)
    original = guard.parse_template(cf.get_template(
        StackName=STACK, ChangeSetName=change_set, TemplateStage='Original')['TemplateBody'])
    processed = guard.parse_template(cf.get_template(
        StackName=STACK, ChangeSetName=change_set, TemplateStage='Processed')['TemplateBody'])
    require(guard.canonical(original) == guard.canonical(
        candidate(guard.parse_template(before['original']))) and
        guard.canonical(processed) == guard.canonical(
        candidate(guard.parse_template(before['processed']))))
    guard.review_inventory(preview['Changes'], guard.parse_template(before['processed']),
                           processed, scope=PURPOSE)
    old_params = {p['ParameterKey']: p.get('ParameterValue') for p in before['parameters']}
    new_params = {p['ParameterKey']: p for p in preview['Parameters']}
    require(len(old_params) == len(before['parameters']) == len(new_params) ==
            len(preview['Parameters']) and set(old_params) == set(new_params) and
            all(item.get('UsePreviousValue') is True or
                item.get('ParameterValue') == old_params[name]
                for name, item in new_params.items()))
    return preview, original, processed


def identity(session):
    caller = session.client('sts').get_caller_identity()
    require(caller['Account'] == ACCOUNT and
            caller['Arn'].startswith(
                f'arn:aws:sts::{ACCOUNT}:assumed-role/zoolanding-content-hub-test-deploy/'))


def source_sha():
    value = os.environ.get('EXPECTED_SOURCE_SHA', '')
    require(re.fullmatch('[0-9a-f]{40}', value) and
            os.environ.get('GITHUB_SHA') == value and
            os.environ.get('GITHUB_REF') == 'refs/heads/test' and
            os.environ.get('GITHUB_REPOSITORY') == 'LynxPardelle/zoolanding-content-hub')
    return value


def review(session, sha):
    cf, s3 = session.client('cloudformation'), session.client('s3')
    before = baseline(cf)
    policy_sha = registry_policy_fingerprint(session)
    bucket = os.environ['SAM_ARTIFACTS_BUCKET']
    # The TEST deploy role cannot inspect bucket settings. The operator's
    # read-only preflight checks identity, versioning and public block. Request
    # SSE-S3 explicitly so this role needs no KMS grant for the review object.
    require(bucket == 'aws-sam-cli-managed-default-samclisourcebucket-obthkeitxden')
    proposed = candidate(guard.parse_template(before['original']))
    body = guard.canonical(proposed)
    key = f'thn/test/emergency-iam/{sha}/{os.environ["GITHUB_RUN_ID"]}/candidate.json'
    # Request SSE-S3 explicitly; this TEST role has no KMS data-key grant.
    # The bucket policy allows this header and the response must confirm it.
    uploaded = s3.put_object(Bucket=bucket, Key=key, Body=body,
                             ServerSideEncryption='AES256', IfNoneMatch='*')
    version = uploaded.get('VersionId')
    require(isinstance(version, str) and version not in ('', 'null') and
            uploaded.get('ServerSideEncryption') == 'AES256')
    url = f'https://{bucket}.s3.{REGION}.amazonaws.com/{quote(key)}'
    name = f'thn-test-emergency-iam-{os.environ["GITHUB_RUN_ID"]}'
    parameters = [{'ParameterKey': p['ParameterKey'], 'UsePreviousValue': True}
                  for p in before['parameters']]
    response = cf.create_change_set(
        StackName=STACK, ChangeSetName=name, ChangeSetType='UPDATE',
        TemplateURL=url, Parameters=parameters,
        Capabilities=['CAPABILITY_NAMED_IAM', 'CAPABILITY_AUTO_EXPAND'],
        Tags=before['tags'])
    change_set = response['Id']
    cf.get_waiter('change_set_create_complete').wait(StackName=STACK,ChangeSetName=change_set)
    preview, original, processed = preview_guard(cf, change_set, before)
    require(guard.sha(baseline(cf)) == guard.sha(before) and
            registry_policy_fingerprint(session) == policy_sha)
    now = int(time.time())
    record = {
        'schemaVersion': 1, 'sourceSha': sha, 'stackId': before['stackId'],
        'changeSetArn': change_set, 'createdAt': now, 'expiresAt': now + 3600,
        'baselineSha256': guard.sha(before), 'candidateSha256': guard.sha(body),
        'originalSha256': guard.sha(original), 'processedSha256': guard.sha(processed),
        'parametersSha256': guard.sha(preview['Parameters']),
        'inventorySha256': guard.sha(preview['Changes']),
        'registryPolicySha256': policy_sha,
        'templateObject': {'bucket': bucket, 'key': key, 'versionId': version},
    }
    record['digest'] = guard.sha(record)
    Path('test-emergency-iam-review.json').write_text(
        json.dumps(record, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'digest': record['digest'], 'changeSetArn': change_set,
                      'inventory': guard.safe_inventory(preview['Changes']),
                      'expiresAt': record['expiresAt']}))


def execute(session, sha):
    record = json.loads(Path('test-emergency-iam-review.json').read_text(encoding='utf-8'))
    approved = os.environ.get('APPROVED_DIGEST', '')
    require(set(record) == RECORD_FIELDS and record['schemaVersion'] == 1 and
            record['sourceSha'] == sha and record['digest'] == approved and
            re.fullmatch('[0-9a-f]{64}', approved) and
            record['digest'] == guard.sha({k: v for k, v in record.items() if k != 'digest'}) and
            record['createdAt'] <= int(time.time()) < record['expiresAt'])
    obj = record['templateObject']
    require(isinstance(obj, dict) and set(obj) == {'bucket', 'key', 'versionId'} and
            obj['bucket'] == 'aws-sam-cli-managed-default-samclisourcebucket-obthkeitxden' and
            re.fullmatch(r'thn/test/emergency-iam/' + sha + r'/[1-9][0-9]*/candidate\.json',
                         obj['key']) and isinstance(obj['versionId'], str) and
            obj['versionId'] not in ('', 'null') and
            record['changeSetArn'].startswith(
                f'arn:aws:cloudformation:{REGION}:{ACCOUNT}:changeSet/thn-test-emergency-iam-'))
    cf, s3 = session.client('cloudformation'), session.client('s3')
    before = baseline(cf)
    require(record['stackId'] == before['stackId'] and
            record['baselineSha256'] == guard.sha(before) and
            record['registryPolicySha256'] == registry_policy_fingerprint(session))
    current = s3.get_object(Bucket=obj['bucket'], Key=obj['key'])
    body = current['Body'].read()
    require(current.get('VersionId') == obj['versionId'] and
            guard.sha(body) == record['candidateSha256'] and
            guard.canonical(json.loads(body)) == guard.canonical(
                candidate(guard.parse_template(before['original']))))
    preview, original, processed = preview_guard(cf, record['changeSetArn'], before)
    require(record['originalSha256'] == guard.sha(original) and
            record['processedSha256'] == guard.sha(processed) and
            record['parametersSha256'] == guard.sha(preview['Parameters']) and
            record['inventorySha256'] == guard.sha(preview['Changes']))
    require(guard.sha(baseline(cf)) == record['baselineSha256'] and
            registry_policy_fingerprint(session) == record['registryPolicySha256'])
    cf.execute_change_set(StackName=STACK,ChangeSetName=record['changeSetArn'])
    cf.get_waiter('stack_update_complete').wait(StackName=STACK)
    after = guard.snapshot(cf, STACK)
    require(registry_policy_fingerprint(session) == record['registryPolicySha256'])
    require(after['status'] == 'UPDATE_COMPLETE' and after['stackId'] == before['stackId'] and
            after['terminationProtection'] is True and after['roleArn'] == before['roleArn'] and
            guard.sha(after['parameters']) == guard.sha(before['parameters']) and
            guard.sha(after['tags']) == guard.sha(before['tags']) and
            guard.sha(after['outputs']) == guard.sha(before['outputs']))
    old_ids = {(r['LogicalResourceId'], r['ResourceType']): r['PhysicalResourceId']
               for r in before['resources']}
    new_ids = {(r['LogicalResourceId'], r['ResourceType']): r['PhysicalResourceId']
               for r in after['resources']}
    require(old_ids == new_ids and len(old_ids) == 64)
    for stage in ('original', 'processed'):
        require(guard.canonical(guard.parse_template(after[stage])) ==
                guard.canonical(candidate(guard.parse_template(before[stage]))))
    print(json.dumps({'verified': True, 'digest': approved, 'stackId': after['stackId']}))


def main():
    require(len(sys.argv) == 2 and sys.argv[1] in {'review', 'execute'})
    sha = source_sha()
    session = boto3.Session(region_name=REGION)
    identity(session)
    if sys.argv[1] == 'review':
        review(session, sha)
    else:
        execute(session, sha)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        code = str(error)
        if not re.fullmatch(r'(production|test)_[a-z0-9_]+', code):
            code = 'test_emergency_iam_guard_failed'
        print(code, file=sys.stderr)
        raise SystemExit(1)
