"""Fail-closed checks for recovering retained production Hub resources."""
from copy import deepcopy
from collections import OrderedDict
from pathlib import Path
from tempfile import TemporaryDirectory
from contextlib import redirect_stdout
import io
import json
import time
import unittest
from unittest.mock import patch

from tools import thn_production_import as target
from tools import thn_production_release as release
from tools import run_thn_production_import as runner


def current_template():
    return {
        'AWSTemplateFormatVersion': '2010-09-09',
        'Transform': 'AWS::Serverless-2016-10-31',
        'Parameters': {'EnvironmentName': {'Type': 'String', 'Default': 'prod'}},
        'Resources': {f'Existing{i:02d}': {'Type': 'AWS::S3::Bucket'} for i in range(10)},
    }


def source_template():
    result = current_template()
    result['Resources'].update({
        logical: {
            'Type': kind,
            'Condition': 'ProvisionState',
            'Metadata': {'SamResourceId': logical},
            'DeletionPolicy': 'Retain',
            'UpdateReplacePolicy': 'Retain',
            'Properties': {
                ('TableName' if kind == 'AWS::DynamoDB::Table' else 'BucketName'): name,
                **({'AttributeDefinitions': [{'AttributeName': 'pk', 'AttributeType': 'S'}],
                    'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                    'BillingMode': 'PAY_PER_REQUEST',
                    'DeletionProtectionEnabled': True,
                    'PointInTimeRecoverySpecification': {'PointInTimeRecoveryEnabled': True}}
                   if kind == 'AWS::DynamoDB::Table' else
                   {'VersioningConfiguration': {'Status': 'Enabled'},
                    'BucketEncryption': {'ServerSideEncryptionConfiguration': [
                        {'ServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]},
                    'PublicAccessBlockConfiguration': dict.fromkeys(
                        ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'), True)}),
            },
        }
        for logical, (kind, name) in target.TARGETS.items()
    })
    result['Resources']['ServiceBindingRegistryV2Table']['Properties']['ResourcePolicy'] = {
        'PolicyDocument': {'Statement': [{'Principal': {'AWS': {'Fn::GetAtt': [
            'ServiceBindingRegistryV2MutationRole', 'Arn']}}}]}}
    return result


def import_changes():
    return [{'Type': 'Resource', 'ResourceChange': {
        'Action': 'Import', 'LogicalResourceId': logical,
        'ResourceType': kind, 'PhysicalResourceId': name,
        'Replacement': 'False', 'Scope': [],
    }} for logical, (kind, name) in target.TARGETS.items()]


class ImportTemplateTests(unittest.TestCase):
    def test_adds_four_retained_resources_without_mutating_current_template(self):
        current = current_template()
        original = deepcopy(current)
        result = target.build_import_template(current, source_template())
        self.assertEqual(current, original)
        self.assertEqual(len(result['Resources']), 14)
        self.assertEqual({k: result['Resources'][k] for k in current['Resources']}, current['Resources'])
        for logical in target.TARGETS:
            resource = result['Resources'][logical]
            self.assertEqual(resource['DeletionPolicy'], 'Retain')
            self.assertEqual(resource['UpdateReplacePolicy'], 'Retain')
            self.assertNotIn('Condition', resource)
            self.assertNotIn('Metadata', resource)
        self.assertNotIn('ResourcePolicy', result['Resources']['ServiceBindingRegistryV2Table']['Properties'])
        rule = result['Resources']['ThnContentHubV2PrivateStore']['Properties'][
            'BucketEncryption']['ServerSideEncryptionConfiguration'][0]
        self.assertEqual(rule['BucketKeyEnabled'], False)
        self.assertEqual(rule['BlockedEncryptionTypes'], {'EncryptionType': ['SSE-C']})

    def test_rejects_missing_or_mutated_source_target(self):
        source = source_template()
        del source['Resources']['ThnContentHubV2AuditTable']
        with self.assertRaises(target.ImportError):
            target.build_import_template(current_template(), source)
        source = source_template()
        source['Resources']['ThnContentHubV2MetadataTable']['Properties']['TableName'] = 'other'
        with self.assertRaises(target.ImportError):
            target.build_import_template(current_template(), source)

    def test_rejects_changed_current_stack_shape(self):
        current = current_template()
        current['Resources']['Extra'] = {'Type': 'AWS::IAM::Role'}
        with self.assertRaises(target.ImportError):
            target.build_import_template(current, source_template())


class StackBaselineTests(unittest.TestCase):
    def baseline(self):
        return {
            'stackId': 'arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-content-hub-prod/123',
            'status': 'UPDATE_ROLLBACK_COMPLETE', 'terminationProtection': True,
            'roleArn': 'arn:aws:iam::765932874577:role/zoolanding-deployer-content-hub-production-cfn-exec',
            'tags': [],
            'original': current_template(),
            'processed': {'Resources': {f'Existing{i:02d}': {} for i in range(17)}},
            'parameters': [{'ParameterKey': 'EnvironmentName', 'ParameterValue': 'prod'}],
            'resources': [{'LogicalResourceId': f'Existing{i:02d}',
                           'PhysicalResourceId': f'physical-{i}',
                           'ResourceType': 'AWS::S3::Bucket'} for i in range(17)],
        }

    def test_accepts_exact_legacy_stack_and_rejects_changed_shape(self):
        baseline = self.baseline()
        self.assertEqual(len(target.validate_stack_baseline(baseline)['resources']), 17)
        for field, value in [('status', 'UPDATE_IN_PROGRESS'),
                             ('terminationProtection', False)]:
            changed = deepcopy(baseline)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(target.ImportError):
                target.validate_stack_baseline(changed)
        changed = deepcopy(baseline)
        changed['resources'][0]['LogicalResourceId'] = 'ServiceBindingRegistryV2Table'
        with self.assertRaises(target.ImportError):
            target.validate_stack_baseline(changed)
        changed = deepcopy(baseline)
        changed['tags'] = [{'Key': 'unexpected', 'Value': 'would-apply-on-import'}]
        with self.assertRaises(target.ImportError):
            target.validate_stack_baseline(changed)

    def test_release_snapshot_accepts_completed_import_for_later_state_review(self):
        class FakeCloudFormation:
            def describe_stacks(self, **kwargs):
                return {'Stacks': [{'StackId': 'stack-id', 'StackStatus': 'IMPORT_COMPLETE',
                                    'EnableTerminationProtection': True, 'Parameters': []}]}
            def list_stack_resources(self, **kwargs):
                return {'StackResourceSummaries': []}
            def get_template(self, **kwargs):
                return {'TemplateBody': {'Resources': {}}}

        self.assertEqual(release.snapshot(FakeCloudFormation(), 'stack')['status'],
                         'IMPORT_COMPLETE')


class ImportInventoryTests(unittest.TestCase):
    def test_accepts_only_four_exact_imports(self):
        self.assertEqual(len(target.validate_import_inventory(import_changes())), 4)

    def test_rejects_other_actions_or_identifiers(self):
        for field, bad in [('Action', 'Add'), ('LogicalResourceId', 'Other'),
                           ('ResourceType', 'AWS::IAM::Role'), ('PhysicalResourceId', 'other'),
                           ('Replacement', 'True')]:
            changes = import_changes()
            changes[0]['ResourceChange'][field] = bad
            with self.subTest(field=field), self.assertRaises(target.ImportError):
                target.validate_import_inventory(changes)
        with self.assertRaises(target.ImportError):
            target.validate_import_inventory(import_changes() + import_changes()[:1])
        changes = import_changes()
        changes[0]['Type'] = 'Parameter'
        with self.assertRaises(target.ImportError):
            target.validate_import_inventory(changes)


class LiveResourceTests(unittest.TestCase):
    def live(self):
        source = source_template()
        tables = {}
        for logical, (kind, name) in target.TARGETS.items():
            if kind != 'AWS::DynamoDB::Table':
                continue
            props = source['Resources'][logical]['Properties']
            tables[logical] = {
                'Table': {'TableName': name, 'TableStatus': 'ACTIVE',
                          'AttributeDefinitions': props['AttributeDefinitions'],
                          'KeySchema': props['KeySchema'],
                          'BillingModeSummary': {'BillingMode': props['BillingMode']},
                          'DeletionProtectionEnabled': True,
                          'SSEDescription': {'Status': 'ENABLED'}},
                'PointInTimeRecoveryDescription': {'PointInTimeRecoveryStatus': 'ENABLED'},
            }
        bucket = {
            'Versioning': {'Status': 'Enabled'},
            'Encryption': {'ServerSideEncryptionConfiguration': {'Rules': [
                {'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'},
                 'BucketKeyEnabled': False,
                 'BlockedEncryptionTypes': {'EncryptionType': ['SSE-C']}}]}},
            'PublicAccessBlock': dict.fromkeys(
                ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'), True),
        }
        return tables, bucket

    def test_accepts_live_table_and_bucket_settings(self):
        tables, bucket = self.live()
        template = target.build_import_template(current_template(), source_template())
        self.assertEqual(len(target.validate_live_resource_settings(template, tables, bucket)), 4)

    def test_rejects_changed_table_or_bucket_security(self):
        template = target.build_import_template(current_template(), source_template())
        tables, bucket = self.live()
        tables['ThnContentHubV2AuditTable']['Table']['DeletionProtectionEnabled'] = False
        with self.assertRaises(target.ImportError):
            target.validate_live_resource_settings(template, tables, bucket)
        tables, bucket = self.live()
        bucket['PublicAccessBlock']['BlockPublicPolicy'] = False
        with self.assertRaises(target.ImportError):
            target.validate_live_resource_settings(template, tables, bucket)


class ImportReviewTests(unittest.TestCase):
    def review(self):
        return target.make_import_review_record(
            source_sha='a' * 40,
            stack_id='arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-content-hub-prod/123',
            baseline_sha='b' * 64,
            target_sha='f' * 64,
            template_sha='c' * 64,
            template_coordinate={'bucket': 'zlp-thn-production-releases-765932874577-us-east-1',
                                 'key': 'thn/production/hub/import/' + 'a' * 40 + '/100/1/import-original.json',
                                 'versionId': 'sealed-version', 'sha256': 'c' * 64},
            registry_policy_revision='12345',
            registry_policy_sha='d' * 64,
            permission_sha='e' * 64,
            native_inventory_sha='1' * 64,
            changes=import_changes(),
            created_at=1000,
        )

    def test_record_contains_only_fingerprints_and_verifies_exact_digest(self):
        record = self.review()
        self.assertNotIn('policy', record)
        self.assertNotIn('parameters', record)
        self.assertEqual(record['templateCoordinate']['sha256'], record['templateSha256'])
        self.assertEqual(record['targetSha256'], 'f' * 64)
        self.assertEqual(record['nativeInventorySha256'], '1' * 64)
        self.assertEqual(record['expiresAt'], 1000 + 86400)
        self.assertEqual(target.verify_import_review_record(
            record, approved_digest=record['digest'], source_sha='a' * 40,
            stack_id=record['stackId'], now=1001), record)

    def test_rejects_tampering_expiry_and_wrong_source(self):
        record = self.review()
        changed = deepcopy(record)
        changed['registryPolicySha256'] = 'f' * 64
        with self.assertRaises(target.ImportError):
            target.verify_import_review_record(
                changed, approved_digest=record['digest'], source_sha='a' * 40,
                stack_id=record['stackId'], now=1001)
        with self.assertRaises(target.ImportError):
            target.verify_import_review_record(
                record, approved_digest=record['digest'], source_sha='a' * 40,
                stack_id=record['stackId'], now=1000 + 86400)
        with self.assertRaises(target.ImportError):
            target.verify_import_review_record(
                record, approved_digest=record['digest'], source_sha='f' * 40,
                stack_id=record['stackId'], now=1001)

    def test_rejects_wrong_template_coordinate(self):
        record = self.review()
        changed = deepcopy(record)
        changed['templateCoordinate']['bucket'] = 'other'
        with self.assertRaises(target.ImportError):
            target.verify_import_review_record(
                changed, approved_digest=record['digest'], source_sha='a' * 40,
                stack_id=record['stackId'], now=1001)


class ImportRunnerTests(unittest.TestCase):
    def test_identifiers_parameters_and_workflow_are_import_only(self):
        identifiers = runner.import_identifiers()
        self.assertEqual(len(identifiers), 4)
        self.assertEqual({item['LogicalResourceId'] for item in identifiers}, set(target.TARGETS))
        self.assertEqual(runner.parameters({'parameters': [
            {'ParameterKey': 'EnvironmentName', 'ParameterValue': 'prod'}]}),
            [{'ParameterKey': 'EnvironmentName', 'UsePreviousValue': True}])
        workflow = (Path(__file__).resolve().parents[1] /
                    '.github/workflows/import-thn-production-retained.yml').read_text()
        self.assertIn('workflow_dispatch:', workflow)
        self.assertIn('environment: production', workflow)
        self.assertIn('group: thn-production-retained-hub', workflow)
        self.assertIn("if: inputs.operation == 'execute'", workflow)
        self.assertNotIn('push:', workflow)

    def test_review_creates_only_import_preview_and_rejects_extra_change(self):
        original = current_template()
        candidate = target.build_import_template(original, source_template())
        processed = {'Resources': {f'Existing{i:02d}': {} for i in range(17)}}
        processed['Resources']['Existing00'] = OrderedDict([
            ('Type', 'AWS::S3::Bucket'),
            ('Properties', OrderedDict([('First', 'one'), ('Second', 'two')])),
        ])
        baseline = {
            'stackId': 'arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-content-hub-prod/123',
            'parameters': [
                {'ParameterKey': 'EnvironmentName', 'ParameterValue': 'prod'},
                {'ParameterKey': 'LogLevel', 'ParameterValue': 'INFO'},
            ],
            'tags': [], 'processed': processed,
        }
        processed_candidate = deepcopy(processed)
        processed_candidate['Resources']['Existing00'] = OrderedDict([
            ('Properties', OrderedDict([('Second', 'two'), ('First', 'one')])),
            ('Type', 'AWS::S3::Bucket'),
        ])
        processed_candidate['Resources'].update({key: value for key, value in
                                                  candidate['Resources'].items() if key in target.TARGETS})
        arn = 'arn:aws:cloudformation:us-east-1:765932874577:changeSet/review/123'

        class FakeWaiter:
            def wait(self, **kwargs):
                self_kwargs = kwargs
                assert self_kwargs['ChangeSetName'] == arn

        class FakeCloudFormation:
            changes = import_changes()
            preview_parameters = baseline['parameters']
            preview_type = None  # DescribeChangeSet omits the request's ChangeSetType.
            preview_original = OrderedDict(reversed(list(candidate.items())))
            preview_processed = processed_candidate
            def create_change_set(self, **kwargs):
                assert kwargs['ChangeSetType'] == 'IMPORT'
                assert len(kwargs['ResourcesToImport']) == 4
                assert kwargs['Parameters'] == runner.parameters(baseline)
                return {'Id': arn}
            def get_waiter(self, name):
                assert name == 'change_set_create_complete'
                return FakeWaiter()
            def describe_change_set(self, **kwargs):
                result = {'Status': 'CREATE_COMPLETE', 'ExecutionStatus': 'AVAILABLE',
                          'StackId': baseline['stackId'],
                          'Parameters': self.preview_parameters, 'Changes': self.changes}
                if self.preview_type is not None:
                    result['ChangeSetType'] = self.preview_type
                return result
            def get_template(self, **kwargs):
                return {'TemplateBody': self.preview_original if kwargs['TemplateStage'] == 'Original'
                        else self.preview_processed}

        class FakeSession:
            def __init__(self):
                self.cf = FakeCloudFormation()
            def client(self, service):
                assert service == 'cloudformation'
                return self.cf

        captured = {'baseline': baseline, 'candidate': OrderedDict(candidate.items())}
        self.assertEqual(len(runner.create_preview(
            FakeSession(), captured,
            {'bucket': 'example', 'key': 'template.json', 'versionId': 'v1'},
            '100/1', 'review')[1]), 4)
        omitted = FakeSession()
        omitted.cf.preview_parameters = None
        self.assertEqual(len(runner.create_preview(
            omitted, captured,
            {'bucket': 'example', 'key': 'template.json', 'versionId': 'v1'},
            '100/1', 'review')[1]), 4)
        reordered = FakeSession()
        reordered.cf.preview_parameters = list(reversed(baseline['parameters']))
        self.assertEqual(len(runner.create_preview(
            reordered, captured,
            {'bucket': 'example', 'key': 'template.json', 'versionId': 'v1'},
            '100/1', 'review')[1]), 4)
        duplicate = FakeSession()
        duplicate.cf.preview_parameters = [baseline['parameters'][0]] * 2
        with self.assertRaises(target.ImportError):
            runner.create_preview(duplicate, captured,
                                  {'bucket': 'example', 'key': 'template.json',
                                   'versionId': 'v1'}, '100/1', 'review')
        altered = FakeSession()
        altered.cf.preview_parameters = deepcopy(baseline['parameters'])
        altered.cf.preview_parameters[1]['ParameterValue'] = 'DEBUG'
        with self.assertRaises(target.ImportError):
            runner.create_preview(altered, captured,
                                  {'bucket': 'example', 'key': 'template.json',
                                   'versionId': 'v1'}, '100/1', 'review')
        altered_processed = FakeSession()
        altered_processed.cf.preview_processed = deepcopy(processed_candidate)
        altered_processed.cf.preview_processed['Resources']['Existing00'][
            'Properties']['First'] = 'changed'
        with self.assertRaises(target.ImportError):
            runner.create_preview(altered_processed, captured,
                                  {'bucket': 'example', 'key': 'template.json',
                                   'versionId': 'v1'}, '100/1', 'review')
        altered_original = FakeSession()
        altered_original.cf.preview_original = deepcopy(altered_original.cf.preview_original)
        altered_original.cf.preview_original['Transform'] = 'wrong'
        with self.assertRaises(target.ImportError):
            runner.create_preview(altered_original, captured,
                                  {'bucket': 'example', 'key': 'template.json',
                                   'versionId': 'v1'}, '100/1', 'review')
        changed = FakeSession()
        changed.cf.changes = import_changes() + [{'Type': 'Resource', 'ResourceChange': {
            'Action': 'Modify', 'LogicalResourceId': 'Existing00',
            'ResourceType': 'AWS::S3::Bucket'}}]
        with self.assertRaises(target.ImportError):
            runner.create_preview(changed, captured,
                                  {'bucket': 'example', 'key': 'template.json',
                                   'versionId': 'v1'}, '100/1', 'review')
        wrong_type = FakeSession()
        wrong_type.cf.preview_type = 'UPDATE'
        with self.assertRaises(target.ImportError):
            runner.create_preview(wrong_type, captured,
                                  {'bucket': 'example', 'key': 'template.json',
                                   'versionId': 'v1'}, '100/1', 'review')

    def test_permission_fingerprint_is_stable_across_review_and_execute_runs(self):
        class FakeIAM:
            def get_role(self, RoleName):
                role = {'Arn': f'arn:aws:iam::765932874577:role/{RoleName}',
                        'RoleId': 'role-' + RoleName,
                        'AssumeRolePolicyDocument': {'Statement': []}}
                if RoleName == runner.CONFIG['executionRole']:
                    role['AssumeRolePolicyDocument']['Statement'] = [{
                        'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                        'Principal': {'Service': 'cloudformation.amazonaws.com'}}]
                return {'Role': role}
            def get_role_policy(self, **kwargs):
                return {'PolicyDocument': {'Version': '2012-10-17', 'Statement': [
                    {'Effect': 'Allow', 'Action': ['dynamodb:GetResourcePolicy'],
                     'Resource': runner.REGISTRY_ARN},
                    {'Effect': 'Allow', 'Action': ['s3:GetBucketVersioning',
                                                 's3:GetEncryptionConfiguration',
                                                 's3:GetBucketPublicAccessBlock', 's3:ListBucket'],
                     'Resource': runner.PRIVATE_BUCKET_ARN}]}}
            def simulate_principal_policy(self, **kwargs):
                return {'EvaluationResults': [
                    {'EvalActionName': action, 'EvalDecision': 'allowed',
                     'EvalResourceName': kwargs['ResourceArns'][0]}
                    for action in kwargs['ActionNames']]}

        class FakeCF:
            def describe_type(self, **kwargs):
                actions = (runner.DDB_PROVIDER_READ if kwargs['TypeName'] ==
                           'AWS::DynamoDB::Table' else runner.S3_PROVIDER_READ)
                return {'Schema': __import__('json').dumps(
                    {'handlers': {'read': {'permissions': sorted(actions)}}})}

        class FakeSession:
            def client(self, name):
                return {'iam': FakeIAM(), 'cloudformation': FakeCF()}[name]

        with patch.object(runner, 'validate_github_trust'):
            first = runner.effective_permissions(FakeSession(), '100/1', 'a' * 40)
            second = runner.effective_permissions(FakeSession(), '200/1', 'a' * 40)
        self.assertEqual(first, second)

    def test_review_deletes_unexecuted_change_set_and_transports_no_policy(self):
        class FakeCF:
            deleted = []
            def delete_change_set(self, **kwargs):
                self.deleted.append(kwargs['ChangeSetName'])

        class FakeSession:
            cf = FakeCF()
            def client(self, name):
                return self.cf if name == 'cloudformation' else object()

        body = b'private-template'
        source_sha = 'a' * 40
        coordinate = {
            'bucket': runner.CONFIG['bucket'],
            'key': f'thn/production/hub/import/{source_sha}/100/1/import-original.json',
            'versionId': 'v1', 'sha256': release.sha(body)}
        captured = {
            'baseline': {'stackId': 'arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-content-hub-prod/123'},
            'templateBytes': body,
            'target': {'policyRevision': '123', 'policySha256': 'd' * 64},
            'permissionSha256': 'e' * 64,
        }
        session = FakeSession()
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'review.json'
            with patch.object(runner.release, 'seal_object', return_value=coordinate), \
                 patch.object(runner, 'create_preview', return_value=(
                     'arn:aws:cloudformation:us-east-1:765932874577:changeSet/review/123',
                     target.validate_import_inventory(import_changes()), '1' * 64)), \
                 patch.object(runner, 'capture', return_value=captured), \
                 redirect_stdout(io.StringIO()):
                runner.review(session, captured, source_sha, '100/1', path)
            record = json.loads(path.read_text())
        self.assertEqual(len(session.cf.deleted), 1)
        self.assertEqual(record['templateCoordinate'], coordinate)
        self.assertNotIn('PolicyDocument', json.dumps(record))
        self.assertNotIn('Statement', json.dumps(record))
        self.assertNotIn('ParameterValue', json.dumps(record))

    def test_review_detects_target_drift_and_deletes_preview_without_raw_values(self):
        arn = 'arn:aws:cloudformation:us-east-1:765932874577:changeSet/review/123'

        class FakeCF:
            deleted = []
            def delete_change_set(self, **kwargs):
                self.deleted.append(kwargs['ChangeSetName'])

        class FakeSession:
            cf = FakeCF()
            def client(self, name):
                return self.cf if name == 'cloudformation' else object()

        source_sha = 'a' * 40
        body = b'private-template'
        coordinate = {
            'bucket': runner.CONFIG['bucket'],
            'key': f'thn/production/hub/import/{source_sha}/100/1/import-original.json',
            'versionId': 'v1', 'sha256': release.sha(body)}
        captured = {
            'baseline': {'stackId': 'arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-content-hub-prod/123'},
            'templateBytes': body,
            'target': {'policyRevision': '123', 'policySha256': 'd' * 64,
                       'tables': {'ServiceBindingRegistryV2Table': {
                           'Table': {'TableId': 'old-id'}}}},
            'permissionSha256': 'e' * 64,
        }
        fresh = deepcopy(captured)
        fresh['target']['tables']['ServiceBindingRegistryV2Table']['Table']['TableId'] = 'private-marker'
        session = FakeSession()
        output = io.StringIO()
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'review.json'
            with patch.object(runner.release, 'seal_object', return_value=coordinate), \
                 patch.object(runner, 'create_preview', return_value=(
                     arn, target.validate_import_inventory(import_changes()), '1' * 64)), \
                 patch.object(runner, 'capture', return_value=fresh), \
                 redirect_stdout(output):
                with self.assertRaises(target.ImportError):
                    runner.review(session, captured, source_sha, '100/1', path)
            self.assertFalse(path.exists())
        self.assertEqual(session.cf.deleted, [arn])
        self.assertIn('target.tables.ServiceBindingRegistryV2Table.Table.TableId', output.getvalue())
        self.assertNotIn('private-marker', output.getvalue())

    def test_diagnostic_preserves_type_sensitive_target_fingerprint(self):
        before = {
            'baseline': {}, 'templateBytes': b'template', 'permissionSha256': 'e' * 64,
            'target': {'tables': {'ServiceBindingRegistryV2Table': {
                'PointInTimeRecoveryDescription': {'RecoveryPeriodInDays': 1}}}},
        }
        after = deepcopy(before)
        after['target']['tables']['ServiceBindingRegistryV2Table'][
            'PointInTimeRecoveryDescription']['RecoveryPeriodInDays'] = 1.0
        self.assertEqual(runner.capture_change_labels(before, after), [
            'target.tables.ServiceBindingRegistryV2Table.PointInTimeRecoveryDescription.RecoveryPeriodInDays'])

    def test_execute_deletes_preview_when_last_read_detects_drift(self):
        source_sha = 'a' * 40
        stack_id = ('arn:aws:cloudformation:us-east-1:765932874577:'
                    'stack/zoolanding-content-hub-prod/123')
        arn = 'arn:aws:cloudformation:us-east-1:765932874577:changeSet/execute/123'
        body = b'private-template'
        captured = {
            'baseline': {'stackId': stack_id},
            'templateBytes': body,
            'target': {'policyRevision': '123', 'policySha256': 'd' * 64,
                       'tables': {'ServiceBindingRegistryV2Table': {
                           'Table': {'TableId': 'old-id'}}}},
            'permissionSha256': 'e' * 64,
        }
        fresh = deepcopy(captured)
        fresh['target']['tables']['ServiceBindingRegistryV2Table']['Table']['TableId'] = 'private-marker'
        coordinate = {
            'bucket': runner.CONFIG['bucket'],
            'key': f'thn/production/hub/import/{source_sha}/100/1/import-original.json',
            'versionId': 'v1', 'sha256': release.sha(body)}
        record = target.make_import_review_record(
            source_sha=source_sha, stack_id=stack_id,
            baseline_sha=release.sha(captured['baseline']),
            target_sha=release.sha(captured['target']), template_sha=release.sha(body),
            template_coordinate=coordinate, registry_policy_revision='123',
            registry_policy_sha='d' * 64, permission_sha='e' * 64,
            native_inventory_sha='1' * 64, changes=import_changes(),
            created_at=int(time.time()))

        class FakeCF:
            deleted = []
            executed = []
            def delete_change_set(self, **kwargs):
                self.deleted.append(kwargs['ChangeSetName'])
            def execute_change_set(self, **kwargs):
                self.executed.append(kwargs['ChangeSetName'])

        class FakeSession:
            cf = FakeCF()
            def client(self, name):
                return self.cf if name == 'cloudformation' else object()

        session = FakeSession()
        output = io.StringIO()
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'review.json'
            path.write_text(json.dumps(record))
            with patch.object(runner.release, 'verify_object', return_value=body), \
                 patch.object(runner, 'create_preview', return_value=(
                     arn, record['changes'], record['nativeInventorySha256'])), \
                 patch.object(runner, 'capture', return_value=fresh), \
                 redirect_stdout(output):
                with self.assertRaisesRegex(target.ImportError,
                                            'production_import_preexecute_state_changed'):
                    runner.execute(session, captured, source_sha, '200/1', path,
                                   record['digest'])
        self.assertEqual(session.cf.deleted, [arn])
        self.assertEqual(session.cf.executed, [])
        self.assertIn('target.tables.ServiceBindingRegistryV2Table.Table.TableId', output.getvalue())
        self.assertNotIn('private-marker', output.getvalue())


if __name__ == '__main__':
    unittest.main()
