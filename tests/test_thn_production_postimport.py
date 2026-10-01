"""The first Hub state release must preserve the four imported identities."""

import copy
import os
import unittest
from unittest.mock import Mock, patch

from tools import run_thn_production_release as driver
from tools import thn_production_import as imported
from tools.thn_production_release import review_inventory


def post_import_baseline():
    old = {f"Legacy{i:02d}": {"Type": "AWS::IAM::Role"} for i in range(17)}
    original = {f"Legacy{i:02d}": old[f"Legacy{i:02d}"] for i in range(10)}
    targets = {}
    resources = [
        {"LogicalResourceId": name, "PhysicalResourceId": f"legacy-{name}",
         "ResourceType": value["Type"]} for name, value in old.items()
    ]
    for logical, (kind, physical) in imported.TARGETS.items():
        property_name = "BucketName" if kind == "AWS::S3::Bucket" else "TableName"
        target = {"Type": kind, "DeletionPolicy": "Retain",
                  "UpdateReplacePolicy": "Retain",
                  "Properties": {property_name: physical}}
        targets[logical] = target
        original[logical] = copy.deepcopy(target)
        old[logical] = copy.deepcopy(target)
        resources.append({"LogicalResourceId": logical,
                          "PhysicalResourceId": physical, "ResourceType": kind})
    return {"stackId": "arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-content-hub-prod/id",
            "status": "IMPORT_COMPLETE", "terminationProtection": True,
            "roleArn": "arn:aws:iam::765932874577:role/zoolanding-deployer-content-hub-production-cfn-exec",
            "tags": [], "parameters": [],
            "original": {"Transform": "AWS::Serverless-2016-10-31",
                         "Parameters": {}, "Resources": original},
            "processed": {"Resources": old}, "resources": resources}, targets


class PostImportStateTests(unittest.TestCase):
    def test_operator_patch_workflow_skips_source_build_but_keeps_protected_release(self):
        from pathlib import Path
        import yaml
        workflow = yaml.safe_load((Path(__file__).resolve().parents[1] /
            '.github/workflows/deploy-thn-production.yml').read_text())
        options = workflow[True]['workflow_dispatch']['inputs']['purpose']['options']
        self.assertIn('operator-patch', options)
        steps = {step['name']: step for step in workflow['jobs']['release']['steps']
                 if 'name' in step}
        for name in ('Set up SAM for review only', 'Validate and build closed production source',
                     'Package new candidate only for review'):
            self.assertIn("inputs.purpose != 'operator-patch'", steps[name]['if'])
        self.assertEqual(workflow['jobs']['release']['environment'], 'production')
        self.assertIn('preflight', steps['Verify effective permissions and live baseline before package writes']['run'])
        self.assertIn('test_thn_production_postimport.py',
            next(step['run'] for step in workflow['jobs']['validate']['steps']
                 if step.get('name') == 'Run offline guards'))

    def test_operator_patch_uses_reviewed_parameters_without_state_secret(self):
        with patch.dict(os.environ, {'THN_PRODUCTION_PARAMETERS_JSON': '{invalid'}):
            self.assertEqual(driver.selected_parameter_overrides('operator-patch'),
                             driver.release.OPERATOR_PARAMETERS)
            with self.assertRaises(ValueError):
                driver.selected_parameter_overrides('state')

    def test_operator_patch_preview_preserves_all_other_parameters(self):
        previous = [
            {'ParameterKey': 'ProvisionThnProductionRegistryOperator', 'ParameterValue': 'false'},
            {'ParameterKey': 'ThnProductionRegistryHumanPrincipalArn', 'ParameterValue': 'BLOCKED'},
            {'ParameterKey': 'EnableThnContentHubV2', 'ParameterValue': 'false'},
            {'ParameterKey': 'ThnProductionOwnerPoolId', 'ParameterValue': '****'},
        ]
        previous += [{'ParameterKey': f'Preserved{i:02d}', 'ParameterValue': f'value-{i}'}
                     for i in range(16)]
        reviewed = copy.deepcopy(previous)
        reviewed[0]['ParameterValue'] = 'true'
        reviewed[1]['ParameterValue'] = driver.release.OPERATOR_PRINCIPAL
        driver.validate_operator_patch_preview_parameters(reviewed, previous)
        self.assertEqual(len(reviewed),20)
        changed = copy.deepcopy(reviewed)
        changed[2]['ParameterValue'] = 'true'
        with self.assertRaises(driver.release.ReleaseError):
            driver.validate_operator_patch_preview_parameters(changed, previous)

    def test_operator_patch_completion_preserves_existing_identities_and_closed_routes(self):
        before = {'status': 'UPDATE_COMPLETE', 'terminationProtection': True,
                  'stackId': 'arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-content-hub-prod/id',
                  'roleArn': 'arn:aws:iam::765932874577:role/zoolanding-deployer-content-hub-production-cfn-exec',
                  'original': {'Resources': {}}, 'processed': {'Resources': {}},
                  'resources': [{'LogicalResourceId': f'Existing{i}', 'PhysicalResourceId': f'id-{i}',
                                 'ResourceType': 'AWS::IAM::Role'} for i in range(57)],
                  'parameters': [{'ParameterKey': 'EnableThnContentHubV2', 'ParameterValue': 'false'},
                                 {'ParameterKey': 'ProvisionThnProductionRegistryOperator', 'ParameterValue': 'false'},
                                 {'ParameterKey': 'ThnProductionRegistryHumanPrincipalArn', 'ParameterValue': 'BLOCKED'}]}
        before['original']['Resources']['ServiceBindingRegistryOperatorInvokePermission']={'Type':'AWS::Lambda::Permission'}
        before['processed']['Resources']['ServiceBindingRegistryOperatorInvokePermission']={'Type':'AWS::Lambda::Permission'}
        after=copy.deepcopy(before)
        del after['original']['Resources']['ServiceBindingRegistryOperatorInvokePermission']
        del after['processed']['Resources']['ServiceBindingRegistryOperatorInvokePermission']
        after['resources'] += [{'LogicalResourceId': name, 'PhysicalResourceId': f'new-{name}',
                                'ResourceStatus': 'CREATE_COMPLETE',
                                'ResourceType': kind} for name, kind in driver.release.OPERATOR_RESOURCES.items()]
        after['resources'][57]['PhysicalResourceId'] = 'zoolanding-thn-registry-production-operator'
        after['parameters'][1]['ParameterValue'] = 'true'
        after['parameters'][2]['ParameterValue'] = driver.release.OPERATOR_PRINCIPAL
        driver.validate_operator_patch_completion(before, after)
        after['resources'][0]['PhysicalResourceId'] = 'replaced'
        with self.assertRaises(driver.release.ReleaseError):
            driver.validate_operator_patch_completion(before, after)

    def test_operator_patch_requires_exact_iam_role_trust_and_inline_invoke(self):
        role={'RoleName':'zoolanding-thn-registry-production-operator',
            'Arn':'arn:aws:iam::765932874577:role/zoolanding-thn-registry-production-operator',
            'MaxSessionDuration':3600,
            'AssumeRolePolicyDocument':{'Version':'2012-10-17','Statement':[{
                'Effect':'Allow','Action':'sts:AssumeRole',
                'Principal':{'AWS':driver.release.OPERATOR_PRINCIPAL},
                'Condition':{'Bool':{'aws:MultiFactorAuthPresent':'true'},
                    'NumericLessThanEquals':{'aws:MultiFactorAuthAge':'300'}}}]}}
        policy={'Version':'2012-10-17','Statement':[{
            'Sid':'InvokeExactPrivateRegistryMutation','Effect':'Allow',
            'Action':['lambda:InvokeFunction'],
            'Resource':'arn:aws:lambda:us-east-1:765932874577:function:zoolanding-content-hub-prod-ThnServiceBindingRegistryV2Mutation'}]}
        driver.validate_operator_iam_policy(role,policy,['InvokeExactThnRegistryMutation'],[])
        changed=copy.deepcopy(policy)
        changed['Statement'][0]['Resource']='*'
        with self.assertRaises(driver.release.ReleaseError):
            driver.validate_operator_iam_policy(role,changed,['InvokeExactThnRegistryMutation'],[])
        changed=copy.deepcopy(role)
        changed['AssumeRolePolicyDocument']['Statement'][0]['Condition'].pop('NumericLessThanEquals')
        with self.assertRaises(driver.release.ReleaseError):
            driver.validate_operator_iam_policy(changed,policy,['InvokeExactThnRegistryMutation'],[])
        with self.assertRaises(driver.release.ReleaseError):
            driver.validate_operator_iam_policy(role,policy,['InvokeExactThnRegistryMutation','Extra'],[])

    def test_operator_patch_keeps_lambda_resource_policy_absent(self):
        missing=Exception('missing')
        missing.response={'Error':{'Code':'ResourceNotFoundException'}}
        client=Mock()
        client.get_policy.side_effect=missing
        driver.validate_operator_lambda_policy_absent(client)
        client.get_policy.side_effect=None
        client.get_policy.return_value={'Policy':'{"Statement":[]}'}
        with self.assertRaises(driver.release.ReleaseError):
            driver.validate_operator_lambda_policy_absent(client)

    def test_operator_patch_effective_role_scope_is_one_lambda_invoke(self):
        exact='arn:aws:lambda:us-east-1:765932874577:function:zoolanding-content-hub-prod-ThnServiceBindingRegistryV2Mutation'
        other='arn:aws:lambda:us-east-1:765932874577:function:zoolanding-content-hub-prod-ThnContentHubV2Authoring'
        result={'IsTruncated':False,'EvaluationResults':[
            {'EvalActionName':'lambda:invokefunction','ResourceSpecificResults':[
                {'EvalResourceName':exact,'EvalResourceDecision':'allowed'},
                {'EvalResourceName':other,'EvalResourceDecision':'implicitDeny'}]},
            {'EvalActionName':'lambda:deletefunction','ResourceSpecificResults':[
                {'EvalResourceName':exact,'EvalResourceDecision':'implicitDeny'},
                {'EvalResourceName':other,'EvalResourceDecision':'implicitDeny'}]}]}
        driver.validate_operator_effective_scope(result)
        changed=copy.deepcopy(result)
        changed['EvaluationResults'][0]['ResourceSpecificResults'][1]['EvalResourceDecision']='allowed'
        with self.assertRaises(driver.release.ReleaseError):
            driver.validate_operator_effective_scope(changed)
        changed=copy.deepcopy(result)
        changed['EvaluationResults'][0]['ResourceSpecificResults'][0]['MissingContextValues']=['aws:MultiFactorAuthPresent']
        with self.assertRaises(driver.release.ReleaseError):
            driver.validate_operator_effective_scope(changed)

    def test_operator_patch_baseline_requires_57_closed_resources_and_dormant_definitions(self):
        from pathlib import Path
        import yaml
        from tools.prepare_thn_production_template import prepare_template
        source = prepare_template(yaml.safe_load((Path(__file__).resolve().parents[1] / 'template.yaml').read_text()))
        expected = driver.release.OPERATOR_RESOURCES
        template = {'Resources': {name: source['Resources'][name] for name in expected}}
        template['Resources']['ServiceBindingRegistryOperatorInvokePermission']={
            'Type':'AWS::Lambda::Permission','Condition':'HasServiceBindingRegistryOperatorRole',
            'Properties':{'Action':'lambda:InvokeFunction',
                'FunctionName':{'Ref':'ServiceBindingRegistryV2MutationFunction'},
                'Principal':{'Fn::Sub':'arn:${AWS::Partition}:iam::${AWS::AccountId}:role/zoolanding-thn-registry-production-operator'}}}
        baseline = {'status': 'UPDATE_COMPLETE', 'terminationProtection': True,
                    'roleArn': 'arn:aws:iam::765932874577:role/zoolanding-deployer-content-hub-production-cfn-exec',
                    'parameters': [{'ParameterKey': name, 'ParameterValue': value} for name, value in {
                        'ProvisionThnServiceBindingRegistryV2State': 'true',
                        'ProvisionThnContentHubV2State': 'true',
                        'ProvisionThnProductionRegistryOperator': 'false',
                        'ThnProductionRegistryHumanPrincipalArn': 'BLOCKED',
                        'EnableThnContentHubV2': 'false',
                        'ThnProductionDependencyGate': 'BLOCKED',
                    }.items()],
                    'resources': [{'LogicalResourceId': f'Existing{i}',
                                   'PhysicalResourceId': f'physical-{i}',
                                   'ResourceType': 'AWS::IAM::Role'} for i in range(57)],
                    'original': copy.deepcopy(template), 'processed': copy.deepcopy(template)}
        driver.validate_operator_patch_baseline(baseline)
        rolled=copy.deepcopy(baseline)
        rolled['status']='UPDATE_ROLLBACK_COMPLETE'
        reviewed_hash='06d5ee8e96c46ccd9e5a52d6305289829075eb8867d2fa95e76ca43c3472efb8'
        real_sha=driver.release.sha
        def pinned_sha(value):
            if isinstance(value,dict) and value.get('status')=='UPDATE_COMPLETE' and value==baseline:
                return reviewed_hash
            return real_sha(value)
        with patch.object(driver.release,'sha',side_effect=pinned_sha):
            driver.validate_operator_patch_baseline(rolled)
        rolled['resources'][0]['PhysicalResourceId']='changed'
        with self.assertRaises(driver.release.ReleaseError):
            driver.validate_operator_patch_baseline(rolled)
        for changed in ('count', 'status', 'protection', 'active-role', 'active-permission', 'definition'):
            invalid = copy.deepcopy(baseline)
            if changed == 'count': invalid['resources'].pop()
            elif changed == 'status': invalid['status'] = 'UPDATE_ROLLBACK_COMPLETE'
            elif changed == 'protection': invalid['terminationProtection'] = False
            elif changed == 'active-role': invalid['resources'][0]['LogicalResourceId'] = next(iter(expected))
            elif changed == 'active-permission': invalid['resources'][0]['LogicalResourceId'] = 'ServiceBindingRegistryOperatorInvokePermission'
            else: invalid['original']['Resources'].pop(next(iter(expected)))
            with self.subTest(changed=changed), self.assertRaises(driver.release.ReleaseError):
                driver.validate_operator_patch_baseline(invalid)

    def test_operator_patch_rejects_missing_dormant_permission_definition(self):
        baseline,_=post_import_baseline()
        with self.assertRaises(driver.release.ReleaseError):
            driver.candidate_for_scope(None,baseline,'operator-patch')

    def test_operator_patch_uses_the_deployed_template_without_repeating_state_transition(self):
        baseline, _ = post_import_baseline()
        baseline['original']['Resources']['ThnProductionRegistryHumanOperatorRole'] = {
            'Type': 'AWS::IAM::Role', 'Condition': 'HasServiceBindingRegistryOperatorRole',
            'Properties': {'RoleName': 'zoolanding-thn-registry-production-operator'}}
        baseline['original']['Resources']['ServiceBindingRegistryOperatorInvokePermission'] = {
            'Type':'AWS::Lambda::Permission','Condition':'HasServiceBindingRegistryOperatorRole'}
        candidate = {'Resources': {'ServiceBindingRegistryV2Table': {
            'Type': 'AWS::DynamoDB::Table', 'Properties': {'ResourcePolicy': 'unreviewed'}}}}
        selected = driver.candidate_for_scope(candidate, baseline, 'operator-patch')
        self.assertEqual(selected['Resources'], {name: value for name, value in baseline['original']['Resources'].items()
                                                 if name!='ServiceBindingRegistryOperatorInvokePermission'})
        self.assertNotEqual(selected, candidate)

    def test_release_failure_code_reports_only_closed_guard_reasons(self):
        self.assertEqual(driver.safe_failure_code(imported.ImportError(
            "production_post_import_registry_policy_changed")),
            "production_post_import_registry_policy_changed")
        self.assertEqual(driver.safe_failure_code(imported.ImportError(
            "unsafe provider text\nsecret")), "ImportError")
        self.assertEqual(driver.safe_failure_code(ValueError("sensitive detail")),
                         "ValueError")

    def test_registry_transition_rebinds_only_four_allows_and_preserves_denies(self):
        role_arn = "arn:aws:iam::765932874577:role/zoolanding-thn-registry-production-mutation"
        old_id = "AROA3EVJIFNI4YJ2FP2VF"
        allowed = (
            "AllowRegistryMutationFunctionDescribe",
            "AllowRegistryMutationFunctionExactRead",
            "AllowRegistryMutationFunctionAtomicPut",
            "AllowRegistryMutationFunctionAtomicConditionCheck",
        )
        live = {"Version": "2012-10-17", "Statement": [
            {"Sid": sid, "Effect": "Allow", "Principal": {"AWS": old_id},
             "Action": "dynamodb:DescribeTable", "Resource": "arn:aws:dynamodb:us-east-1:765932874577:table/registry"}
            for sid in allowed
        ] + [
            {"Sid": f"DenyOther{i:02d}", "Effect": "Deny", "Principal": "*",
             "Action": ["dynamodb:DeleteItem"], "Resource": "arn:aws:dynamodb:us-east-1:765932874577:table/registry"}
            for i in range(22)
        ]}
        proposed = copy.deepcopy(live)
        proposed["Statement"].reverse()
        for statement in proposed["Statement"]:
            statement["Action"] = ([statement["Action"]] if isinstance(statement["Action"], str)
                                    else statement["Action"][0])
            statement["Resource"] = {"Fn::Sub": "arn:${AWS::Partition}:dynamodb:${AWS::Region}:${AWS::AccountId}:table/registry"}
            if statement["Sid"] in allowed:
                statement["Principal"]["AWS"] = {"Fn::GetAtt": ["ServiceBindingRegistryV2MutationRole", "Arn"]}
        proof = imported.validate_registry_policy_transition(live, proposed, role_arn)
        self.assertEqual(proof["reboundSids"], sorted(allowed))
        self.assertNotEqual(proof["beforeSemanticSha256"], proof["targetSemanticSha256"])
        weakened = copy.deepcopy(proposed)
        next(item for item in weakened["Statement"] if item["Sid"] == "DenyOther00")["Action"] = "dynamodb:Scan"
        with self.assertRaises(imported.ImportError):
            imported.validate_registry_policy_transition(live, weakened, role_arn)
        wrong_role = copy.deepcopy(live)
        wrong_role["Statement"][0]["Principal"]["AWS"] = "AROAOTHER"
        with self.assertRaises(imported.ImportError):
            imported.validate_registry_policy_transition(wrong_role, proposed, role_arn)

    def test_completed_registry_policy_binds_new_role_without_losing_denies(self):
        role_arn = imported.MUTATION_ROLE_ARN
        new_id = "AROANEWROLEID"
        allowed = sorted(imported.MUTATION_ALLOW_SIDS)
        target = {"Version": "2012-10-17", "Statement": [
            {"Sid": sid, "Effect": "Allow", "Principal": {"AWS": role_arn},
             "Action": "dynamodb:DescribeTable", "Resource": "registry"}
            for sid in allowed
        ] + [
            {"Sid": f"DenyOther{i:02d}", "Effect": "Deny", "Principal": "*",
             "Action": "dynamodb:DeleteItem", "Resource": "registry"}
            for i in range(22)
        ]}
        live = copy.deepcopy(target)
        for statement in live["Statement"][:4]:
            statement["Principal"]["AWS"] = new_id
        imported.validate_completed_registry_policy(live, target, role_arn)
        with self.assertRaises(imported.ImportError):
            imported.validate_completed_registry_policy(live, target, role_arn,
                                                       imported.ORPHAN_MUTATION_ROLE_ID)
        weakened = copy.deepcopy(live)
        weakened["Statement"][-1]["Action"] = "dynamodb:Scan"
        with self.assertRaises(imported.ImportError):
            imported.validate_completed_registry_policy(weakened, target, role_arn)
        inconsistent = copy.deepcopy(live)
        inconsistent["Statement"][0]["Principal"]["AWS"] = "AROADIFFERENT"
        with self.assertRaises(imported.ImportError):
            imported.validate_completed_registry_policy(inconsistent, target, role_arn)

    def test_state_baseline_fingerprints_live_imported_resources_and_policy(self):
        baseline, _ = post_import_baseline()
        session = Mock()
        live = {"policyRevision": "1790716784435",
                "policySemanticSha256": "746729dad0f26e808c342c6c07fdc055a99ff197e43f7e8d1249d663985dbaf8",
                "policyDocument": {"Version": "2012-10-17", "Statement": []},
                "identities": {"stable": True}, "tables": {}, "bucket": {}}
        with patch.dict(os.environ, {"THN_PRODUCTION_SELECTED_PURPOSE": "state"}), \
                patch.object(driver.release, "snapshot", return_value=baseline), \
                patch("tools.run_thn_production_import.read_targets", return_value=live) as capture:
            result = driver.captured_baseline(session)
        capture.assert_called_once()
        self.assertEqual(result["postImportTargets"], live)
        changed = {**live, "policySemanticSha256": "0" * 64}
        with patch.dict(os.environ, {"THN_PRODUCTION_SELECTED_PURPOSE": "state"}), \
                patch.object(driver.release, "snapshot", return_value=baseline), \
                patch("tools.run_thn_production_import.read_targets", return_value=changed):
            with self.assertRaises(imported.ImportError):
                driver.captured_baseline(session)

    def test_state_baseline_requires_all_four_imported_identities(self):
        baseline, _ = post_import_baseline()
        imported.validate_post_import_state_baseline(baseline)
        intrinsic = copy.deepcopy(baseline)
        intrinsic["original"]["Resources"]["ThnContentHubV2PrivateStore"]["Properties"]["BucketName"] = {
            "Fn::Sub": "zlp-thn-ch-production-private-${AWS::AccountId}-${AWS::Region}"}
        imported.validate_post_import_state_baseline(intrinsic)
        for mutation in ("missing", "replaced", "unprotected"):
            changed = copy.deepcopy(baseline)
            if mutation == "missing":
                changed["resources"].pop()
            elif mutation == "replaced":
                changed["resources"][-1]["PhysicalResourceId"] = "other-bucket"
            else:
                changed["terminationProtection"] = False
            with self.subTest(mutation=mutation), self.assertRaises(imported.ImportError):
                imported.validate_post_import_state_baseline(changed)

    def test_state_candidate_preserves_other_imported_declarations_and_public_api(self):
        baseline, targets = post_import_baseline()
        baseline["original"]["Resources"]["ContentHubApi"] = {"Type": "AWS::Serverless::HttpApi", "Properties": {"StageName": "prod"}}
        baseline["original"]["Resources"]["ContentHubFunction"] = {
            "Type": "AWS::Serverless::Function",
            "Properties": {"CodeUri": "s3://historical/function.zip"}}
        baseline["original"]["Parameters"]["LegacySetting"] = {
            "Type": "String", "Default": "historical"}
        registry = copy.deepcopy(targets["ServiceBindingRegistryV2Table"])
        registry["Condition"] = "ProvisionRegistry"
        registry["Properties"]["ResourcePolicy"] = {"PolicyDocument": {"Statement": [
            {"Sid": "DenyUnapproved", "Effect": "Deny"}]}}
        candidate = {"Parameters": {"LegacySetting": {"Type": "String", "Default": "new"}}, "Resources": {
            **{name: {**value, "Condition": "ProvisionState", "Properties": {"changed": True}}
               for name, value in targets.items()},
            "ServiceBindingRegistryV2Table": registry,
            "ContentHubApi": {"Type": "AWS::Serverless::HttpApi", "Properties": {"StageName": "other"}},
            "ContentHubFunction": {"Type": "AWS::Serverless::Function",
                                   "Properties": {"CodeUri": "s3://new/function.zip"}},
            "ServiceBindingRegistryV2MutationRole": {"Type": "AWS::IAM::Role"},
            "ThnContentHubV2AuthoringRole": {"Type": "AWS::IAM::Role"},
        }}
        selected = driver.candidate_for_scope(candidate, baseline, "state")
        for logical in (*[name for name in targets if name != "ServiceBindingRegistryV2Table"], "ContentHubApi"):
            self.assertEqual(selected["Resources"][logical], baseline["original"]["Resources"][logical])
        expected = copy.deepcopy(registry)
        expected.pop("Condition")
        self.assertEqual(selected["Resources"]["ServiceBindingRegistryV2Table"], expected)
        self.assertIn("ThnContentHubV2AuthoringRole", selected["Resources"])
        baseline["original"]["Resources"]["ContentHubFunction"]["Properties"]["CodeUri"] = {
            "Bucket": "recovery", "Key": "previous.zip", "Version": "v1"}
        baseline["original"]["Resources"]["ContentHubApi"]["Properties"]["StageName"] = "recovery"
        baseline["original"]["Resources"]["ThnContentHubV2AuditTable"]["Properties"]["changed"] = True
        baseline["original"]["Parameters"]["LegacySetting"]["Default"] = "recovery"
        self.assertEqual(selected["Resources"]["ContentHubFunction"]["Properties"]["CodeUri"],
                         "s3://historical/function.zip")
        self.assertEqual(selected["Resources"]["ContentHubApi"]["Properties"]["StageName"], "prod")
        self.assertNotIn("changed", selected["Resources"]["ThnContentHubV2AuditTable"]["Properties"])
        self.assertEqual(selected["Parameters"]["LegacySetting"]["Default"], "historical")

    def test_state_candidate_restores_only_registry_policy(self):
        baseline, targets = post_import_baseline()
        baseline["original"]["Resources"]["ContentHubApi"] = {
            "Type": "AWS::Serverless::HttpApi", "Properties": {"StageName": "prod"}}
        registry = copy.deepcopy(targets["ServiceBindingRegistryV2Table"])
        registry["Properties"]["ResourcePolicy"] = {
            "PolicyDocument": {"Version": "2012-10-17", "Statement": [
                {"Sid": "DenyUnapproved", "Effect": "Deny", "Principal": "*",
                 "Action": "dynamodb:DeleteItem", "Resource": "registry"}]}}
        candidate = {"Parameters": {}, "Resources": {
            **{name: {**value, "Properties": {"changed": True}}
               for name, value in targets.items()},
            "ServiceBindingRegistryV2Table": registry,
            "ServiceBindingRegistryV2MutationRole": {"Type": "AWS::IAM::Role"},
        }}
        selected = driver.candidate_for_scope(candidate, baseline, "state")
        self.assertEqual(selected["Resources"]["ServiceBindingRegistryV2Table"], registry)
        for logical in set(targets) - {"ServiceBindingRegistryV2Table"}:
            self.assertEqual(selected["Resources"][logical], baseline["original"]["Resources"][logical])

    def test_state_inventory_accepts_only_nonreplacing_registry_policy_modify(self):
        baseline, _ = post_import_baseline()
        registry = {"ResourceChange": {"Action": "Modify",
                    "LogicalResourceId": "ServiceBindingRegistryV2Table",
                    "ResourceType": "AWS::DynamoDB::Table", "Replacement": "False",
                    "Details": [{"Target": {"Attribute": "Properties", "Name": "ResourcePolicy"},
                                 "Evaluation": "Static", "ChangeSource": "DirectModification"}]}}
        imported.validate_post_import_state_inventory([registry], baseline)
        with self.assertRaises(imported.ImportError):
            imported.validate_post_import_state_inventory([], baseline)
        for change in (
            {**registry["ResourceChange"], "Replacement": "Conditional"},
            {**registry["ResourceChange"], "Details": [{"Target": {
                "Attribute": "Properties", "Name": "DeletionProtectionEnabled"}}]},
            {**registry["ResourceChange"], "LogicalResourceId": "ThnContentHubV2AuditTable"},
        ):
            with self.subTest(change=change), self.assertRaises(imported.ImportError):
                imported.validate_post_import_state_inventory(
                    [{"ResourceChange": change}], baseline)

    def test_state_completion_accepts_new_role_and_preserves_imported_identities(self):
        before, _ = post_import_baseline()
        after = copy.deepcopy(before)
        after["status"] = "UPDATE_COMPLETE"
        after["original"]["Resources"]["ServiceBindingRegistryV2Table"]["Properties"]["ResourcePolicy"] = {
            "PolicyDocument": {"Statement": [{"Sid": "DenyUnapproved"}]}}
        after["original"]["Resources"]["ServiceBindingRegistryV2MutationRole"] = {"Type": "AWS::IAM::Role"}
        after["processed"]["Resources"]["ServiceBindingRegistryV2MutationRole"] = {"Type": "AWS::IAM::Role"}
        after["resources"].append({"LogicalResourceId": "ServiceBindingRegistryV2MutationRole",
                                   "PhysicalResourceId": "zoolanding-thn-registry-production-mutation",
                                   "ResourceType": "AWS::IAM::Role"})
        changes = [{"ResourceChange": {"Action": "Add", "Replacement": None,
                    "LogicalResourceId": "ServiceBindingRegistryV2MutationRole",
                    "ResourceType": "AWS::IAM::Role"}},
                   {"ResourceChange": {"Action": "Modify", "Replacement": "False",
                    "LogicalResourceId": "ServiceBindingRegistryV2Table",
                    "ResourceType": "AWS::DynamoDB::Table", "Details": [{"Target": {
                        "Attribute": "Properties", "Name": "ResourcePolicy"}}]}}]
        imported.validate_post_import_state_completion(before, after, changes)
        with_dormant_condition = copy.deepcopy(after)
        with_dormant_condition["processed"]["Resources"]["InactiveOptionalRole"] = {
            "Type": "AWS::IAM::Role", "Condition": "OptionalRoleEnabled"}
        imported.validate_post_import_state_completion(before, with_dormant_condition, changes)
        for mutation in ("replacement", "unexpected", "unconditional_missing", "status", "opened_routes"):
            invalid = copy.deepcopy(after)
            if mutation == "replacement":
                next(row for row in invalid["resources"] if row["LogicalResourceId"] ==
                     "ServiceBindingRegistryV2Table")["PhysicalResourceId"] = "replacement"
            elif mutation == "unexpected":
                invalid["resources"].append({"LogicalResourceId": "Unknown",
                                             "PhysicalResourceId": "unknown", "ResourceType": "AWS::IAM::Role"})
            elif mutation == "unconditional_missing":
                invalid["processed"]["Resources"]["MissingRole"] = {"Type": "AWS::IAM::Role"}
            elif mutation == "status":
                invalid["status"] = "UPDATE_ROLLBACK_COMPLETE"
            else:
                invalid["parameters"] = [{"ParameterKey": "EnableThnContentHubV2",
                                          "ParameterValue": "true"}]
            with self.subTest(mutation=mutation), self.assertRaises(imported.ImportError):
                imported.validate_post_import_state_completion(before, invalid, changes)

    def test_state_inventory_rejects_existing_resource_modification(self):
        baseline, _ = post_import_baseline()
        added = [{"ResourceChange": {"Action": "Add", "LogicalResourceId": "ThnContentHubV2AuthoringRole",
                                      "ResourceType": "AWS::IAM::Role", "Replacement": "False"}}]
        registry = {"ResourceChange": {"Action": "Modify",
                    "LogicalResourceId": "ServiceBindingRegistryV2Table",
                    "ResourceType": "AWS::DynamoDB::Table", "Replacement": "False",
                    "Details": [{"Target": {"Attribute": "Properties", "Name": "ResourcePolicy"}}]}}
        imported.validate_post_import_state_inventory(added + [registry], baseline)
        nullable = copy.deepcopy(added)
        nullable[0]["ResourceChange"]["Replacement"] = None
        review_inventory(nullable, baseline["processed"],
                         {"Resources": {"ThnContentHubV2AuthoringRole": {"Type": "AWS::IAM::Role"}}},
                         scope="state")
        imported.validate_post_import_state_inventory(nullable + [registry], baseline)
        for logical in ("ThnContentHubV2PrivateStore", "Legacy00"):
            changed = added + [registry, {"ResourceChange": {"Action": "Modify", "LogicalResourceId": logical,
                                               "ResourceType": "AWS::S3::Bucket", "Replacement": "False"}}]
            with self.subTest(logical=logical), self.assertRaises(imported.ImportError):
                imported.validate_post_import_state_inventory(changed, baseline)


if __name__ == "__main__":
    unittest.main()
