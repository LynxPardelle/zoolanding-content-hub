"""Offline fail-closed checks for the TEST emergency Registry read release."""
from copy import deepcopy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from tools import thn_production_release as guard
from tools import thn_production_import as imported
from tools import thn_test_emergency_iam as release


def old_template():
    source = release.source_template()
    old = deepcopy(source)
    statements = old['Resources'][release.ROLE]['Properties']['Policies'][0]['PolicyDocument']['Statement']
    statements[:] = [item for item in statements
                     if item.get('Sid') != 'ReadExactThnBindingBeforeWithdrawal']
    return old


def change():
    return {'Type': 'Resource', 'ResourceChange': {
        'Action': 'Modify', 'LogicalResourceId': release.ROLE,
        'PhysicalResourceId': release.ROLE_NAME, 'ResourceType': 'AWS::IAM::Role',
        'Replacement': 'False', 'Scope': ['Properties'],
        'Details': [{'ChangeSource': 'DirectModification',
                     'Target': {'Attribute': 'Properties', 'Name': 'Policies',
                                'RequiresRecreation': 'Never'}}]}}


class TestEmergencyIam(unittest.TestCase):
    def test_registry_policy_fingerprint_ignores_principal_order_but_rejects_change(self):
        policy = {'Version': '2012-10-17', 'Statement': [
            {'Sid': f'Rule{i}', 'Effect': 'Deny',
             'Principal': {'AWS': ['arn:aws:iam::765932874577:role/First',
                                   'arn:aws:iam::765932874577:role/Second']},
             'Action': ['dynamodb:GetItem'], 'Resource': [release.REGISTRY_ARN]}
            for i in range(26)]}
        expected = guard.sha(imported.normalize_registry_policy(policy))
        client = Mock()
        session = Mock()
        session.client.return_value = client
        with patch.object(release, 'REGISTRY_POLICY_SHA256', expected):
            client.get_resource_policy.return_value = {
                'RevisionId': release.REGISTRY_POLICY_REVISION,
                'Policy': json.dumps(policy)}
            self.assertEqual(release.registry_policy_fingerprint(session), expected)
            reordered = deepcopy(policy)
            reordered['Statement'].reverse()
            reordered['Statement'][0]['Principal']['AWS'].reverse()
            client.get_resource_policy.return_value['Policy'] = json.dumps(reordered)
            self.assertEqual(release.registry_policy_fingerprint(session), expected)
            altered = deepcopy(reordered)
            altered['Statement'][0]['Principal']['AWS'][0] = 'arn:aws:iam::765932874577:role/Other'
            client.get_resource_policy.return_value['Policy'] = json.dumps(altered)
            with self.assertRaises(guard.ReleaseError):
                release.registry_policy_fingerprint(session)

    def test_review_and_execute_recheck_exact_candidate(self):
        source_sha = 'a' * 40
        old = old_template()
        proposed = release.candidate(old)
        before = {
            'stackId': 'arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-content-hub-test/id',
            'status': 'UPDATE_COMPLETE', 'terminationProtection': True, 'roleArn': None,
            'original': old, 'parameters': [{'ParameterKey': 'EnvironmentName', 'ParameterValue': 'test'}],
            'processed': old, 'tags': [{'Key': 'thn:environment', 'Value': 'test'}],
            'outputs': [],
            'resources': [{'LogicalResourceId': f'R{i}', 'ResourceType': 'AWS::IAM::Role',
                           'PhysicalResourceId': f'role-{i}'} for i in range(64)]}
        preview = {'Changes': [change()], 'Parameters': before['parameters']}
        session = Mock()
        cf, s3 = Mock(), Mock()
        session.client.side_effect = {'cloudformation': cf, 's3': s3}.__getitem__
        s3.put_object.return_value = {'VersionId': 'v1', 'ServerSideEncryption': 'AES256'}
        cf.create_change_set.return_value = {
            'Id': 'arn:aws:cloudformation:us-east-1:765932874577:changeSet/thn-test-emergency-iam-100/id'}
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {
            'SAM_ARTIFACTS_BUCKET': 'aws-sam-cli-managed-default-samclisourcebucket-obthkeitxden',
            'GITHUB_RUN_ID': '100'}), patch.object(release, 'baseline', return_value=before), \
             patch.object(release, 'registry_policy_fingerprint', return_value='b' * 64), \
             patch.object(release, 'preview_guard', return_value=(preview, proposed, proposed)):
            try:
                os.chdir(temporary)
                with redirect_stdout(io.StringIO()):
                    release.review(session, source_sha)
                self.assertTrue(Path('test-emergency-iam-review.json').is_file())
                record = json.loads(Path('test-emergency-iam-review.json').read_text())
                after = deepcopy(before)
                after['original'] = proposed
                after['processed'] = proposed
                with patch.dict(os.environ, {'APPROVED_DIGEST': record['digest']}), \
                     patch.object(guard, 'snapshot', return_value=after), \
                     redirect_stdout(io.StringIO()):
                    s3.get_object.return_value = {
                        'VersionId': 'v1', 'Body': io.BytesIO(b'{}')}
                    with self.assertRaises(guard.ReleaseError):
                        release.execute(session, source_sha)
                    self.assertEqual(cf.execute_change_set.call_count, 0)
                    s3.get_object.return_value = {
                        'VersionId': 'v1', 'Body': io.BytesIO(guard.canonical(proposed))}
                    release.execute(session, source_sha)
            finally:
                os.chdir(previous)
        self.assertEqual(s3.put_object.call_args.kwargs['Body'], guard.canonical(proposed))
        self.assertEqual(cf.create_change_set.call_count, 1)
        self.assertEqual(cf.execute_change_set.call_count, 1)

    def test_change_set_reads_always_include_exact_stack(self):
        cf = Mock()
        cf.describe_change_set.side_effect = [
            {'Status': 'CREATE_COMPLETE', 'ExecutionStatus': 'AVAILABLE',
             'Changes': [], 'NextToken': 'page-2'},
            {'Status': 'CREATE_COMPLETE', 'ExecutionStatus': 'AVAILABLE',
             'Changes': [change()]},
        ]
        self.assertEqual(len(release.describe_preview(cf, 'change-set')['Changes']), 1)
        for call in cf.describe_change_set.call_args_list:
            self.assertEqual(call.kwargs['StackName'], release.STACK)

    def test_exact_source_grant_and_absent_baseline(self):
        old = old_template()
        candidate = release.candidate(old)
        self.assertEqual(release.statement(candidate), release.statement(release.source_template()))
        candidate['Resources'][release.ROLE] = deepcopy(old['Resources'][release.ROLE])
        self.assertEqual(candidate, old)
        with self.assertRaises(guard.ReleaseError):
            release.candidate(release.source_template())
        changed = deepcopy(old)
        changed['Resources'][release.ROLE]['Properties']['RoleName'] = 'other'
        with self.assertRaises(guard.ReleaseError):
            release.candidate(changed)

    def test_preview_requires_one_role_policy_modify_and_unchanged_parameters(self):
        old = old_template()
        candidate = release.candidate(old)
        before = {
            'stackId': 'arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-content-hub-test/id',
            'original': old, 'processed': old,
            'parameters': [{'ParameterKey': 'EnvironmentName', 'ParameterValue': 'test'}]}
        preview = {'StackId': before['stackId'], 'Changes': [change()],
                   'Parameters': [{'ParameterKey': 'EnvironmentName', 'ParameterValue': 'test'}]}
        cf = Mock()
        cf.get_template.side_effect = [
            {'TemplateBody': candidate}, {'TemplateBody': candidate}]
        with patch.object(release, 'describe_preview', return_value=preview):
            release.preview_guard(cf, 'change-set', before)
            bad = deepcopy(preview)
            bad['Changes'][0]['ResourceChange']['Replacement'] = 'True'
            cf.get_template.side_effect = [
                {'TemplateBody': candidate}, {'TemplateBody': candidate}]
            with patch.object(release, 'describe_preview', return_value=bad), self.assertRaises(guard.ReleaseError):
                release.preview_guard(cf, 'change-set', before)


if __name__ == '__main__':
    unittest.main()
