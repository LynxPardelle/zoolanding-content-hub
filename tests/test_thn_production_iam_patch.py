"""Source-free IAM reviews change only one known role policy."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from tools import thn_production_release as release
from tools import run_thn_production_release as driver


def old_template(purpose):
    source = driver.iam_patch_source()
    old = deepcopy(source)
    logical, sid = release.IAM_PATCHES[purpose]
    statements = old['Resources'][logical]['Properties']['Policies'][0]['PolicyDocument']['Statement']
    if purpose == 'writer-iam-patch':
        statement = next(item for item in statements if item.get('Sid') == sid)
        statement['Resource'][0] = {'Fn::Sub': 'arn:aws:lambda:us-east-1:765932874577:function:old-writer'}
    else:
        statements[:] = [item for item in statements if item.get('Sid') != sid]
    return old, source


def change(purpose):
    logical, _ = release.IAM_PATCHES[purpose]
    return [{'Type': 'Resource', 'ResourceChange': {
        'Action': 'Modify', 'LogicalResourceId': logical,
        'PhysicalResourceId': 'expected-role', 'ResourceType': 'AWS::IAM::Role',
        'Replacement': 'False', 'Scope': ['Properties'],
        'Details': [{'ChangeSource': 'DirectModification',
                     'Target': {'Attribute': 'Properties', 'Name': 'Policies',
                                'RequiresRecreation': 'Never'}}]}}]


class IamPatchTest(unittest.TestCase):
    def test_baseline_requires_live_policy_fingerprint_and_exact_old_statement(self):
        purpose = 'writer-iam-patch'
        old, _ = old_template(purpose)
        baseline = {'status': 'UPDATE_COMPLETE', 'terminationProtection': True,
                    'roleArn': f'arn:aws:iam::{release.ACCOUNT}:role/{driver.CONFIG["executionRole"]}',
                    'resources': [{} for _ in range(59)], 'original': old, 'processed': old,
                    'iamPatchRegistryPolicy': {'revision': '123', 'sha256': release.sha({})}}
        old_hash = release.sha(driver.iam_patch_statement(old, purpose))
        with patch.dict(driver.IAM_PATCH_BASELINE_STATEMENTS, {purpose: old_hash}):
            driver.validate_iam_patch_baseline(baseline, purpose)
            changed = deepcopy(baseline)
            changed.pop('iamPatchRegistryPolicy')
            with self.assertRaises(release.ReleaseError):
                driver.validate_iam_patch_baseline(changed, purpose)

    def test_candidate_changes_only_one_role_statement(self):
        for purpose in release.IAM_PATCHES:
            with self.subTest(purpose=purpose):
                old, source = old_template(purpose)
                candidate = release.iam_patch_candidate_template(old, source, purpose)
                logical, _ = release.IAM_PATCHES[purpose]
                self.assertEqual(driver.iam_patch_statement(candidate, purpose),
                                 driver.iam_patch_statement(source, purpose))
                candidate['Resources'][logical] = deepcopy(old['Resources'][logical])
                self.assertEqual(candidate, old)
                with self.assertRaises(release.ReleaseError):
                    release.iam_patch_candidate_template(source, source, purpose)

    def test_native_inventory_requires_only_one_policy_modify_without_replacement(self):
        for purpose in release.IAM_PATCHES:
            old, source = old_template(purpose)
            candidate = release.iam_patch_candidate_template(old, source, purpose)
            rows = change(purpose)
            self.assertEqual(release.review_inventory(rows, old, candidate, scope=purpose), rows)
            for mutation in ('Replacement', 'LogicalResourceId', 'Name'):
                bad = deepcopy(rows)
                item = bad[0]['ResourceChange']
                if mutation == 'Name':
                    item['Details'][0]['Target']['Name'] = 'AssumeRolePolicyDocument'
                else:
                    item[mutation] = 'True' if mutation == 'Replacement' else 'OtherRole'
                with self.subTest(purpose=purpose, mutation=mutation), self.assertRaises(release.ReleaseError):
                    release.review_inventory(bad, old, candidate, scope=purpose)
            with self.assertRaises(release.ReleaseError):
                release.review_inventory(rows + rows, old, candidate, scope=purpose)

    def test_preview_checks_full_original_processed_and_physical_role(self):
        purpose = 'emergency-iam-patch'
        old, source = old_template(purpose)
        candidate = release.iam_patch_candidate_template(old, source, purpose)
        logical, _ = release.IAM_PATCHES[purpose]
        rows = change(purpose)
        baseline = {'original': old, 'processed': old,
                    'parameters': [{'ParameterKey': 'EnvironmentName', 'ParameterValue': 'prod'}],
                    'resources': [{'LogicalResourceId': logical, 'ResourceType': 'AWS::IAM::Role',
                                   'PhysicalResourceId': 'expected-role'}]}
        preview = {'Changes': rows, 'Parameters': [
            {'ParameterKey': 'EnvironmentName', 'UsePreviousValue': True}]}
        with patch.object(driver, 'iam_patch_source', return_value=source):
            driver.validate_iam_patch_preview(preview, baseline, purpose, candidate, candidate)
            altered = deepcopy(candidate)
            altered['Resources'][logical]['Properties']['RoleName'] = 'wrong'
            with self.assertRaises(release.ReleaseError):
                driver.validate_iam_patch_preview(preview, baseline, purpose, altered, candidate)
            bad = deepcopy(preview)
            bad['Changes'][0]['ResourceChange']['PhysicalResourceId'] = 'wrong'
            with self.assertRaises(release.ReleaseError):
                driver.validate_iam_patch_preview(bad, baseline, purpose, candidate, candidate)


if __name__ == '__main__':
    unittest.main()
