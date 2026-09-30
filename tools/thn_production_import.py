"""Pure guards for importing retained production Content Hub resources."""
from copy import deepcopy
from types import MappingProxyType
import hashlib
import json
import re


class ImportError(ValueError):
    """A closed production import invariant failed."""


TARGETS = MappingProxyType({
    'ServiceBindingRegistryV2Table': (
        'AWS::DynamoDB::Table', 'zoolanding-content-hub-prod-ServiceBindingRegistryV2'),
    'ThnContentHubV2AuditTable': (
        'AWS::DynamoDB::Table', 'zoolanding-content-hub-prod-ThnContentHubV2Audit'),
    'ThnContentHubV2MetadataTable': (
        'AWS::DynamoDB::Table', 'zoolanding-content-hub-prod-ThnContentHubV2Metadata'),
    'ThnContentHubV2PrivateStore': (
        'AWS::S3::Bucket', 'zlp-thn-ch-production-private-765932874577-us-east-1'),
})

REVIEW_FIELDS = frozenset({
    'schemaVersion', 'contract', 'sourceSha', 'stackId', 'createdAt', 'expiresAt',
    'baselineSha256', 'targetSha256', 'templateSha256', 'templateCoordinate',
    'registryPolicyRevision',
    'registryPolicySha256', 'permissionSha256', 'changes', 'digest',
    'nativeInventorySha256',
})


def require(condition, reason='production_import_invalid'):
    if not condition:
        raise ImportError(reason)


def _physical_name(resource, kind):
    props = resource['Properties']
    value = props['TableName' if kind == 'AWS::DynamoDB::Table' else 'BucketName']
    if isinstance(value, dict) and set(value) == {'Fn::Sub'}:
        value = value['Fn::Sub'].replace('${AWS::AccountId}', '765932874577').replace(
            '${AWS::Region}', 'us-east-1')
    return value


def validate_stack_baseline(baseline):
    """Reject any stack other than the protected pre-import 17-resource state."""
    require(isinstance(baseline, dict))
    require(isinstance(baseline.get('stackId'), str) and baseline['stackId'].startswith(
        'arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-content-hub-prod/')
        and baseline.get('status') == 'UPDATE_ROLLBACK_COMPLETE'
        and baseline.get('terminationProtection') is True
        and baseline.get('tags') == []
        and baseline.get('roleArn') ==
        'arn:aws:iam::765932874577:role/zoolanding-deployer-content-hub-production-cfn-exec',
        'production_import_stack_state_changed')
    original = baseline.get('original')
    processed = baseline.get('processed')
    resources = baseline.get('resources')
    parameters = baseline.get('parameters')
    require(isinstance(original, dict) and isinstance(processed, dict)
            and isinstance(resources, list) and isinstance(parameters, list))
    require(original.get('Transform') == 'AWS::Serverless-2016-10-31'
            and len(original.get('Resources', {})) == 10
            and len(processed.get('Resources', {})) == 17
            and len(resources) == 17
            and {r.get('LogicalResourceId') for r in resources} == set(processed['Resources'])
            and not set(TARGETS).intersection(processed['Resources'])
            and {p.get('ParameterKey') for p in parameters} ==
            set(original.get('Parameters', {})),
            'production_import_baseline_shape_changed')
    return baseline


def build_import_template(current_original, production_source):
    """Append four import declarations without changing any existing definition."""
    require(isinstance(current_original, dict) and isinstance(production_source, dict))
    require(current_original.get('Transform') == 'AWS::Serverless-2016-10-31')
    require(production_source.get('Transform') == current_original['Transform'])
    existing = current_original.get('Resources')
    source = production_source.get('Resources')
    require(isinstance(existing, dict) and len(existing) == 10 and isinstance(source, dict),
            'production_import_stack_shape_changed')
    require(not set(TARGETS).intersection(existing), 'production_import_already_managed')
    result = deepcopy(current_original)
    for logical, (kind, expected_name) in TARGETS.items():
        candidate = deepcopy(source.get(logical))
        require(isinstance(candidate, dict) and candidate.get('Type') == kind,
                'production_import_source_resource_missing')
        require(candidate.get('DeletionPolicy') == 'Retain' and
                candidate.get('UpdateReplacePolicy') == 'Retain',
                'production_import_retention_missing')
        props = candidate.get('Properties')
        require(isinstance(props, dict) and _physical_name(candidate, kind) == expected_name,
                'production_import_name_changed')
        if kind == 'AWS::DynamoDB::Table':
            require({'AttributeDefinitions', 'KeySchema', 'BillingMode',
                     'DeletionProtectionEnabled', 'PointInTimeRecoverySpecification'} <= set(props)
                    and props['DeletionProtectionEnabled'] is True
                    and props['PointInTimeRecoverySpecification'].get('PointInTimeRecoveryEnabled') is True,
                    'production_import_table_safety_missing')
        else:
            require(props.get('VersioningConfiguration', {}).get('Status') == 'Enabled'
                    and all(props.get('PublicAccessBlockConfiguration', {}).get(key) is True
                            for key in ('BlockPublicAcls', 'IgnorePublicAcls',
                                        'BlockPublicPolicy', 'RestrictPublicBuckets')),
                    'production_import_bucket_safety_missing')
            rules = props.get('BucketEncryption', {}).get('ServerSideEncryptionConfiguration')
            require(rules == [{'ServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}],
                    'production_import_bucket_encryption_source_changed')
            # These two live settings were absent from the historical source.
            # Declare them for import so CloudFormation does not erase or drift them.
            rules[0]['BucketKeyEnabled'] = False
            rules[0]['BlockedEncryptionTypes'] = {'EncryptionType': ['SSE-C']}
        candidate.pop('Condition', None)
        require(candidate.pop('Metadata', {'SamResourceId': logical}) ==
                {'SamResourceId': logical}, 'production_import_metadata_changed')
        if logical == 'ServiceBindingRegistryV2Table':
            props.pop('ResourcePolicy', None)
        require(set(candidate) <= {'Type', 'Properties', 'DeletionPolicy', 'UpdateReplacePolicy'},
                'production_import_unexpected_resource_attribute')
        result['Resources'][logical] = candidate
    require({k: result['Resources'][k] for k in existing} == existing,
            'production_import_current_resources_changed')
    return result


def validate_import_inventory(changes):
    """Accept only the four exact CloudFormation Import resource changes."""
    require(isinstance(changes, list) and len(changes) == len(TARGETS),
            'production_import_inventory_size')
    seen = set()
    result = []
    for item in changes:
        require(isinstance(item, dict) and item.get('Type') == 'Resource'
                and isinstance(item.get('ResourceChange'), dict))
        change = item['ResourceChange']
        logical = change.get('LogicalResourceId')
        require(logical in TARGETS and logical not in seen,
                'production_import_inventory_logical_id')
        kind, physical = TARGETS[logical]
        require(change.get('Action') == 'Import' and change.get('ResourceType') == kind
                and change.get('PhysicalResourceId') == physical
                and change.get('Replacement') in (None, 'False', False)
                and not change.get('Scope'),
                'production_import_inventory_resource')
        seen.add(logical)
        result.append({'LogicalResourceId': logical, 'ResourceType': kind,
                       'PhysicalResourceId': physical, 'Action': 'Import'})
    require(seen == set(TARGETS))
    return sorted(result, key=lambda row: row['LogicalResourceId'])


def validate_live_resource_settings(import_template, tables, bucket):
    """Require the four retained identities and safety settings before import."""
    require(isinstance(import_template, dict) and isinstance(tables, dict)
            and isinstance(bucket, dict))
    require(set(tables) == {name for name, (kind, _) in TARGETS.items()
                            if kind == 'AWS::DynamoDB::Table'})
    checked = []
    for logical, (kind, physical) in TARGETS.items():
        props = import_template['Resources'][logical]['Properties']
        if kind == 'AWS::DynamoDB::Table':
            live = tables[logical]
            require(isinstance(live, dict) and isinstance(live.get('Table'), dict))
            table = live['Table']
            require(table.get('TableName') == physical and table.get('TableStatus') == 'ACTIVE'
                    and table.get('AttributeDefinitions') == props['AttributeDefinitions']
                    and table.get('KeySchema') == props['KeySchema']
                    and table.get('BillingModeSummary', {}).get('BillingMode') == props['BillingMode']
                    and table.get('DeletionProtectionEnabled') is True
                    and table.get('SSEDescription', {}).get('Status') == 'ENABLED'
                    and live.get('PointInTimeRecoveryDescription', {}).get(
                        'PointInTimeRecoveryStatus') == 'ENABLED',
                    'production_import_live_table_changed')
        else:
            rules = props['BucketEncryption']['ServerSideEncryptionConfiguration']
            live_rules = bucket.get('Encryption', {}).get(
                'ServerSideEncryptionConfiguration', {}).get('Rules')
            expected_rules = [{
                'ApplyServerSideEncryptionByDefault': rule['ServerSideEncryptionByDefault'],
                'BucketKeyEnabled': rule['BucketKeyEnabled'],
                'BlockedEncryptionTypes': rule['BlockedEncryptionTypes'],
            } for rule in rules]
            require(bucket.get('Versioning', {}).get('Status') == 'Enabled'
                    and live_rules == expected_rules
                    and bucket.get('PublicAccessBlock') ==
                    props['PublicAccessBlockConfiguration'],
                    'production_import_live_bucket_changed')
        checked.append({'logicalId': logical, 'physicalId': physical, 'type': kind})
    return sorted(checked, key=lambda item: item['logicalId'])


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _hex(value, length):
    return isinstance(value, str) and bool(re.fullmatch('[a-f0-9]{%d}' % length, value))


def validate_template_coordinate(coordinate, source_sha, template_sha):
    require(isinstance(coordinate, dict) and set(coordinate) ==
            {'bucket', 'key', 'versionId', 'sha256'})
    require(coordinate['bucket'] ==
            'zlp-thn-production-releases-765932874577-us-east-1'
            and isinstance(coordinate['key'], str)
            and bool(re.fullmatch(r'thn/production/hub/import/' + source_sha +
                                  r'/[1-9][0-9]*/[1-9][0-9]*/import-original\.json',
                                  coordinate['key']))
            and isinstance(coordinate['versionId'], str)
            and coordinate['versionId'] not in ('', 'null')
            and coordinate['sha256'] == template_sha,
            'production_import_template_coordinate_invalid')
    return deepcopy(coordinate)


def make_import_review_record(*, source_sha, stack_id, baseline_sha, target_sha,
                              template_sha,
                              template_coordinate,
                              registry_policy_revision, registry_policy_sha,
                              permission_sha, native_inventory_sha, changes, created_at):
    """Transport only exact identities and fingerprints, never policy or parameters."""
    require(_hex(source_sha, 40) and all(_hex(value, 64) for value in (
        baseline_sha, target_sha, template_sha, registry_policy_sha,
        permission_sha, native_inventory_sha)))
    require(isinstance(stack_id, str) and stack_id.startswith(
        'arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-content-hub-prod/'))
    require(isinstance(registry_policy_revision, str) and
            bool(re.fullmatch('[0-9]+', registry_policy_revision)))
    require(type(created_at) is int and created_at > 0)
    record = {
        'schemaVersion': 1,
        'contract': 'thn-production-hub-retained-import/v1',
        'sourceSha': source_sha,
        'stackId': stack_id,
        'createdAt': created_at,
        'expiresAt': created_at + 86400,
        'baselineSha256': baseline_sha,
        'targetSha256': target_sha,
        'templateSha256': template_sha,
        'templateCoordinate': validate_template_coordinate(
            template_coordinate, source_sha, template_sha),
        'registryPolicyRevision': registry_policy_revision,
        'registryPolicySha256': registry_policy_sha,
        'permissionSha256': permission_sha,
        'nativeInventorySha256': native_inventory_sha,
        'changes': validate_import_inventory(changes),
    }
    record['digest'] = _digest(record)
    return record


def verify_import_review_record(record, *, approved_digest, source_sha, stack_id, now):
    require(isinstance(record, dict) and set(record) == REVIEW_FIELDS)
    require(record.get('schemaVersion') == 1 and
            record.get('contract') == 'thn-production-hub-retained-import/v1')
    require(_hex(approved_digest, 64) and record['digest'] == approved_digest and
            _digest({key: value for key, value in record.items() if key != 'digest'}) == approved_digest,
            'production_import_digest_changed')
    require(record['sourceSha'] == source_sha and record['stackId'] == stack_id)
    require(type(now) is int and type(record['createdAt']) is int and
            type(record['expiresAt']) is int and
            record['createdAt'] <= now < record['expiresAt'] and
            record['expiresAt'] - record['createdAt'] == 86400,
            'production_import_review_expired')
    require(_hex(record['sourceSha'], 40) and all(_hex(record[key], 64) for key in (
        'baselineSha256', 'targetSha256', 'templateSha256',
        'registryPolicySha256', 'permissionSha256', 'nativeInventorySha256')))
    validate_template_coordinate(record['templateCoordinate'], record['sourceSha'],
                                 record['templateSha256'])
    require(isinstance(record['registryPolicyRevision'], str) and
            bool(re.fullmatch('[0-9]+', record['registryPolicyRevision'])))
    expected = sorted(({'LogicalResourceId': logical, 'ResourceType': kind,
                        'PhysicalResourceId': physical, 'Action': 'Import'}
                       for logical, (kind, physical) in TARGETS.items()),
                      key=lambda row: row['LogicalResourceId'])
    require(record['changes'] == expected)
    return deepcopy(record)
