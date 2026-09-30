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


def validate_post_import_state_baseline(baseline):
    """Accept only the protected, complete import as the first Hub state base."""
    require(isinstance(baseline, dict) and isinstance(baseline.get('stackId'), str)
            and baseline['stackId'].startswith(
                'arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-content-hub-prod/')
            and baseline.get('status') == 'IMPORT_COMPLETE'
            and baseline.get('terminationProtection') is True
            and baseline.get('roleArn') ==
                'arn:aws:iam::765932874577:role/zoolanding-deployer-content-hub-production-cfn-exec'
            and baseline.get('tags') == [], 'production_post_import_stack_changed')
    original = baseline.get('original')
    processed = baseline.get('processed')
    resources = baseline.get('resources')
    parameters = baseline.get('parameters')
    require(isinstance(original, dict) and isinstance(processed, dict)
            and isinstance(resources, list) and isinstance(parameters, list)
            and original.get('Transform') == 'AWS::Serverless-2016-10-31'
            and len(original.get('Resources', {})) == 14
            and len(processed.get('Resources', {})) == 21
            and len(resources) == 21
            and {r.get('LogicalResourceId') for r in resources} == set(processed['Resources'])
            and {p.get('ParameterKey') for p in parameters} ==
                set(original.get('Parameters', {})),
            'production_post_import_shape_changed')
    by_logical = {row.get('LogicalResourceId'): row for row in resources}
    for logical, (kind, physical) in TARGETS.items():
        item = original['Resources'].get(logical)
        native = processed['Resources'].get(logical)
        row = by_logical.get(logical)
        name_key = 'BucketName' if kind == 'AWS::S3::Bucket' else 'TableName'
        declared_name = item.get('Properties', {}).get(name_key) if isinstance(item, dict) else None
        if kind == 'AWS::S3::Bucket':
            approved_names = (physical, {'Fn::Sub':
                'zlp-thn-ch-production-private-${AWS::AccountId}-${AWS::Region}'})
        else:
            approved_names = (physical,)
        require(isinstance(item, dict) and isinstance(native, dict) and isinstance(row, dict)
                and item.get('Type') == kind and native.get('Type') == kind
                and item.get('DeletionPolicy') == 'Retain'
                and item.get('UpdateReplacePolicy') == 'Retain'
                and declared_name in approved_names
                and row.get('ResourceType') == kind
                and row.get('PhysicalResourceId') == physical,
                'production_post_import_identity_changed')
    return baseline


def validate_post_import_state_inventory(changes, baseline):
    """Initial state may add THN resources and rebind Registry policy only."""
    require(isinstance(changes, list) and isinstance(baseline, dict)
            and isinstance(baseline.get('resources'), list),
            'production_post_import_inventory_invalid')
    previous = {row.get('LogicalResourceId') for row in baseline['resources']}
    require(sum(item.get('ResourceChange', {}).get('LogicalResourceId') ==
                'ServiceBindingRegistryV2Table' and
                item.get('ResourceChange', {}).get('Action') == 'Modify'
                for item in changes) == 1,
            'production_post_import_registry_transition_missing')
    for item in changes:
        change = item.get('ResourceChange', {})
        logical = change.get('LogicalResourceId')
        if logical == 'ServiceBindingRegistryV2Table' and change.get('Action') == 'Modify':
            details=change.get('Details',[])
            require(change.get('ResourceType')=='AWS::DynamoDB::Table' and
                    change.get('Replacement')=='False' and details and
                    all(detail.get('Target',{}).get('Attribute')=='Properties' and
                        detail.get('Target',{}).get('Name')=='ResourcePolicy' and
                        detail.get('Target',{}).get('RequiresRecreation','Never')=='Never'
                        for detail in details),
                    'production_post_import_registry_transition_unreviewed')
            continue
        require(change.get('Action') == 'Add' and change.get('Replacement') in (None, 'False')
                and isinstance(logical, str) and logical not in previous
                and logical.startswith(('Thn', 'ServiceBinding')),
                'production_post_import_existing_resource_changed')
    return changes


MUTATION_ALLOW_SIDS = frozenset({
    'AllowRegistryMutationFunctionDescribe',
    'AllowRegistryMutationFunctionExactRead',
    'AllowRegistryMutationFunctionAtomicPut',
    'AllowRegistryMutationFunctionAtomicConditionCheck',
})
ORPHAN_MUTATION_ROLE_ID = 'AROA3EVJIFNI4YJ2FP2VF'
MUTATION_ROLE_ARN = (
    'arn:aws:iam::765932874577:role/zoolanding-thn-registry-production-mutation')


def normalize_registry_policy(policy):
    """Canonicalize IAM's equivalent list/scalar and statement-order forms."""
    require(isinstance(policy, dict) and set(policy) == {'Version', 'Statement'}
            and policy['Version'] == '2012-10-17'
            and isinstance(policy['Statement'], list)
            and len(policy['Statement']) == 26,
            'production_registry_policy_shape_changed')
    statements = []
    for source in policy['Statement']:
        require(isinstance(source, dict) and
                {'Sid', 'Effect', 'Principal', 'Action', 'Resource'} <= set(source) <=
                {'Sid', 'Effect', 'Principal', 'Action', 'Resource', 'Condition'}
                and isinstance(source['Sid'], str) and source['Sid']
                and source['Effect'] in {'Allow', 'Deny'},
                'production_registry_policy_shape_changed')
        statement = deepcopy(source)
        for name in ('Action', 'Resource'):
            value = statement[name]
            if isinstance(value, str):
                value = [value]
            require(isinstance(value, list) and value and
                    all(isinstance(item, str) and item for item in value) and
                    len(value) == len(set(value)),
                    'production_registry_policy_shape_changed')
            statement[name] = sorted(value)
        principal = statement['Principal']
        if isinstance(principal, dict):
            require(set(principal) == {'AWS'},
                    'production_registry_policy_shape_changed')
            values = principal['AWS']
            if isinstance(values, str):
                values = [values]
            require(isinstance(values, list) and values and
                    all(isinstance(value, str) and value for value in values) and
                    len(values) == len(set(values)),
                    'production_registry_policy_shape_changed')
            principal['AWS'] = sorted(values)
        else:
            require(principal == '*', 'production_registry_policy_shape_changed')
        for entries in statement.get('Condition', {}).values():
            require(isinstance(entries, dict),
                    'production_registry_policy_shape_changed')
            for key, value in entries.items():
                if isinstance(value, str):
                    value = [value]
                require(isinstance(value, list) and value and
                        all(isinstance(item, str) for item in value) and
                        len(value) == len(set(value)),
                        'production_registry_policy_shape_changed')
                entries[key] = sorted(value)
        statements.append(statement)
    sids = [statement['Sid'] for statement in statements]
    require(len(sids) == len(set(sids)), 'production_registry_policy_duplicate_sid')
    return {'Version': '2012-10-17',
            'Statement': sorted(statements, key=lambda item: item['Sid'])}


def resolve_registry_policy(policy, role_arn):
    """Resolve only the three AWS pseudo values and one reviewed role ARN."""
    require(role_arn == MUTATION_ROLE_ARN,
            'production_registry_mutation_role_changed')

    def resolve(value):
        if isinstance(value, dict):
            if set(value) == {'Fn::GetAtt'}:
                require(value['Fn::GetAtt'] ==
                        ['ServiceBindingRegistryV2MutationRole', 'Arn'],
                        'production_registry_policy_intrinsic_unreviewed')
                return role_arn
            if set(value) == {'Fn::Sub'}:
                require(isinstance(value['Fn::Sub'], str),
                        'production_registry_policy_intrinsic_unreviewed')
                text = value['Fn::Sub']
                for key, replacement in (
                    ('AWS::Partition', 'aws'), ('AWS::Region', 'us-east-1'),
                    ('AWS::AccountId', '765932874577')):
                    text = text.replace('${' + key + '}', replacement)
                require('${' not in text,
                        'production_registry_policy_intrinsic_unreviewed')
                return text
            require(not any(key.startswith('Fn::') or key == 'Ref' for key in value),
                    'production_registry_policy_intrinsic_unreviewed')
            return {key: resolve(child) for key, child in value.items()}
        if isinstance(value, list):
            return [resolve(child) for child in value]
        return value

    return resolve(policy)


def validate_registry_policy_transition(live_policy, proposed_policy, role_arn):
    """Allow only replacement of the deleted mutation role principal."""
    before = normalize_registry_policy(live_policy)
    target = normalize_registry_policy(resolve_registry_policy(proposed_policy, role_arn))
    rebound = deepcopy(before)
    changed = []
    for statement in rebound['Statement']:
        if statement['Sid'] in MUTATION_ALLOW_SIDS:
            require(statement['Principal'] == {'AWS': [ORPHAN_MUTATION_ROLE_ID]},
                    'production_registry_orphan_principal_changed')
            statement['Principal'] = {'AWS': [role_arn]}
            changed.append(statement['Sid'])
    require(set(changed) == MUTATION_ALLOW_SIDS and rebound == target,
            'production_registry_policy_transition_unreviewed')
    return {'beforeSemanticSha256': _digest(before),
            'targetSemanticSha256': _digest(target),
            'reboundSids': sorted(changed)}


def validate_completed_registry_policy(live_policy, proposed_policy, role_arn,
                                       new_role_id=None):
    """Require the new role principal and all reviewed Registry deny rules."""
    actual = normalize_registry_policy(live_policy)
    target = normalize_registry_policy(resolve_registry_policy(proposed_policy, role_arn))
    rebound = deepcopy(actual)
    principals=[]
    for statement in rebound['Statement']:
        if statement['Sid'] in MUTATION_ALLOW_SIDS:
            values=statement['Principal'].get('AWS') if isinstance(
                statement['Principal'],dict) else None
            require(isinstance(values,list) and len(values)==1,
                    'production_registry_new_principal_missing')
            principals.append(values[0])
            statement['Principal'] = {'AWS': [role_arn]}
    require(len(principals)==len(MUTATION_ALLOW_SIDS) and
            len(set(principals))==1,
            'production_registry_new_principal_missing')
    observed=principals[0]
    if new_role_id is not None:
        require(new_role_id==observed,
                'production_registry_new_principal_missing')
    require(observed==role_arn or (observed.startswith('AROA') and
            observed!=ORPHAN_MUTATION_ROLE_ID),
            'production_registry_mutation_role_not_recreated')
    require(rebound == target,
            'production_registry_completed_policy_changed')
    return {'liveSemanticSha256': _digest(actual),
            'targetSemanticSha256': _digest(target),
            'reboundSids': sorted(MUTATION_ALLOW_SIDS)}


def validate_post_import_state_completion(before, after, changes):
    """Verify a completed state release without reapplying the import baseline."""
    validate_post_import_state_baseline(before)
    validate_post_import_state_inventory(changes, before)
    require(isinstance(after, dict) and after.get('status') == 'UPDATE_COMPLETE'
            and after.get('stackId') == before['stackId']
            and after.get('terminationProtection') is True
            and after.get('roleArn') == before['roleArn']
            and after.get('tags') == before['tags']
            and isinstance(after.get('parameters'),list)
            and all(item.get('ParameterValue')=='false' for item in
                after['parameters'] if item.get('ParameterKey','').startswith('EnableThn')),
            'production_post_import_state_completion_invalid')
    previous = {row['LogicalResourceId']: row for row in before['resources']}
    current = {row['LogicalResourceId']: row for row in after.get('resources', [])}
    additions = {item['ResourceChange']['LogicalResourceId']
                 for item in changes if item['ResourceChange']['Action'] == 'Add'}
    require(len(current) == len(after.get('resources', [])) and
            set(current) == set(previous) | additions and
            all(current[name].get('PhysicalResourceId') == row.get('PhysicalResourceId')
                and current[name].get('ResourceType') == row.get('ResourceType')
                for name, row in previous.items()) and
            all(current[name].get('ResourceType') == next(
                item['ResourceChange']['ResourceType'] for item in changes
                if item['ResourceChange']['LogicalResourceId'] == name)
                for name in additions) and
            'ServiceBindingRegistryV2MutationRole' in additions,
            'production_post_import_state_identity_changed')
    original = after.get('original', {})
    processed = after.get('processed', {})
    native = processed.get('Resources', {}) if isinstance(processed, dict) else {}
    require(isinstance(original, dict) and isinstance(processed, dict) and
            isinstance(native, dict) and set(current) <= set(native) and
            all(isinstance(native[name].get('Condition'), str) and
                native[name]['Condition'] for name in set(native) - set(current)),
            'production_post_import_state_template_changed')
    before_resources = before['original']['Resources']
    after_resources = original.get('Resources', {})
    require(all(after_resources.get(name) == item for name, item in
                before_resources.items() if name != 'ServiceBindingRegistryV2Table'),
            'production_post_import_existing_template_changed')
    registry_before = before_resources['ServiceBindingRegistryV2Table']
    registry_after = deepcopy(after_resources.get('ServiceBindingRegistryV2Table'))
    require(isinstance(registry_after, dict) and
            isinstance(registry_after.get('Properties', {}).get('ResourcePolicy'), dict),
            'production_post_import_registry_policy_missing')
    registry_after['Properties'].pop('ResourcePolicy')
    require(registry_after == registry_before,
            'production_post_import_registry_other_property_changed')
    return after


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
