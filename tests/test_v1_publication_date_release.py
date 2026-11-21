import base64
from copy import deepcopy
import hashlib
import io
import unittest
import zipfile
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch

from test_v1_publication_date_patch import BEFORE, AFTER
from tools.v1_publication_date_patch import PatchRejected
from tools.release_v1_publication_date import patch_deployed_zip, candidate_template, validate_templates, validate_preview, stable_configuration, validate_live_baseline
from tools import thn_production_release as retained
from tools import release_v1_publication_date as release


CODE={'bucket':'private-releases','key':'reviewed/code.zip','versionId':'immutable-version','sha256':'a'*64}
ORIGINAL={'Parameters':{'Secret':{'Type':'String','NoEcho':True}},'Resources':{
 'ContentHubFunction':{'Type':'AWS::Serverless::Function','Properties':{'CodeUri':'s3://old/code.zip','Handler':'lambda_function.lambda_handler','Environment':{'Variables':{'UNCHANGED':'private-value'}}}},
 'ThnUnchanged':{'Type':'AWS::Lambda::Function','Properties':{'Code':{'S3Bucket':'old','S3Key':'v2.zip'},'Role':'unchanged'}},
 'Api':{'Type':'AWS::ApiGatewayV2::Api','Properties':{'Body':{'paths':{'/unchanged':{}}}}}}}
PROCESSED=deepcopy(ORIGINAL)
PROCESSED['Resources']['ContentHubFunction']['Type']='AWS::Lambda::Function'
PROCESSED['Resources']['ContentHubFunction']['Properties']['Code']={'S3Bucket':'old','S3Key':'code.zip'}
del PROCESSED['Resources']['ContentHubFunction']['Properties']['CodeUri']
PREVIEW={'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE','Changes':[{'ResourceChange':{
 'Action':'Modify','LogicalResourceId':'ContentHubFunction','PhysicalResourceId':'zoolanding-content-hub-prod-Function',
 'ResourceType':'AWS::Lambda::Function','Replacement':'False','Scope':['Properties'],
 'Details':[{'ChangeSource':'DirectModification','Evaluation':'Static','Target':{'Attribute':'Properties','Name':'Code','RequiresRecreation':'Never'}}]}}]}


def archive(source,extra=None):
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED) as result:
        result.writestr('lambda_function.py',source)
        result.writestr('boto3/dependency.py',b'unchanged dependency bytes')
        for name,value in (extra or {}).items():result.writestr(name,value)
    return stream.getvalue()


class V1PublicationDateReleaseTests(unittest.TestCase):
    def candidates(self):
        original=candidate_template(ORIGINAL,CODE)
        processed=deepcopy(PROCESSED)
        processed['Resources']['ContentHubFunction']['Properties']['Code']={'S3Bucket':CODE['bucket'],'S3Key':CODE['key'],'S3ObjectVersion':CODE['versionId']}
        return original,processed

    def test_zip_changes_only_the_exact_runtime_module(self):
        original=archive(BEFORE)
        patched=patch_deployed_zip(original,BEFORE.encode(),AFTER.encode())
        with zipfile.ZipFile(io.BytesIO(original)) as before, zipfile.ZipFile(io.BytesIO(patched)) as after:
            self.assertEqual(before.namelist(),after.namelist())
            self.assertEqual(after.read('lambda_function.py'),AFTER.encode())
            for name in before.namelist():
                if name!='lambda_function.py':self.assertEqual(before.read(name),after.read(name))

    def test_zip_rejects_source_drift_extra_runtime_and_unsafe_names(self):
        for body in (archive(BEFORE.replace('approved','drifted')),archive(BEFORE,{'../escape':'x'}),archive(BEFORE,{'publisher_lambda.py':'v2'})):
            with self.subTest(body=hashlib.sha256(body).hexdigest()), self.assertRaises(PatchRejected):patch_deployed_zip(body,BEFORE.encode(),AFTER.encode())
        with self.assertRaises(PatchRejected):patch_deployed_zip(archive(BEFORE),BEFORE.encode(),AFTER.replace('"updatedAt": now','"updatedAt": published_at').encode())

    def test_templates_allow_only_existing_function_code(self):
        original,processed=self.candidates()
        self.assertTrue(validate_templates(ORIGINAL,PROCESSED,original,processed,CODE))
        self.assertEqual(original['Resources']['ThnUnchanged'],ORIGINAL['Resources']['ThnUnchanged'])
        self.assertEqual(original['Parameters'],ORIGINAL['Parameters'])

    def test_v2_iam_routes_environment_parameters_or_resources_never_pass(self):
        for target in ('v2','role','route','env','parameter','new-resource','delete','version'):
            original,processed=self.candidates()
            if target=='v2':processed['Resources']['ThnUnchanged']['Properties']['Code']['S3Key']='changed.zip'
            if target=='role':processed['Resources']['ContentHubFunction']['Properties']['Role']='new-role'
            if target=='route':original['Resources']['Api']['Properties']['Body']['paths']['/new']={}
            if target=='env':processed['Resources']['ContentHubFunction']['Properties']['Environment']['Variables']['UNCHANGED']='changed'
            if target=='parameter':original['Parameters']['New']={'Type':'String'}
            if target=='new-resource':processed['Resources']['New']={'Type':'AWS::IAM::Role'}
            if target=='delete':del processed['Resources']['ThnUnchanged']
            if target=='version':processed['Resources']['ContentHubFunction']['Properties']['Code']['S3ObjectVersion']='changed'
            with self.subTest(target=target),self.assertRaises(PatchRejected):validate_templates(ORIGINAL,PROCESSED,original,processed,CODE)

    def test_native_preview_rejects_every_noncode_change_or_replacement(self):
        self.assertTrue(validate_preview(PREVIEW))
        for target in ('extra','add','replace','v2','physical','environment','dynamic','no-detail','scope','unavailable'):
            preview=deepcopy(PREVIEW);change=preview['Changes'][0]['ResourceChange']
            if target=='extra':preview['Changes'].append(deepcopy(preview['Changes'][0]))
            if target=='add':change['Action']='Add'
            if target=='replace':change['Replacement']='True'
            if target=='v2':change['LogicalResourceId']='ThnUnchanged'
            if target=='physical':change['PhysicalResourceId']='another-function'
            if target=='environment':change['Details'][0]['Target']['Name']='Environment'
            if target=='dynamic':change['Details'][0]['Evaluation']='Dynamic'
            if target=='no-detail':change['Details']=[]
            if target=='scope':change['Scope']=['Properties','Metadata']
            if target=='unavailable':preview['ExecutionStatus']='EXECUTE_COMPLETE'
            with self.subTest(target=target),self.assertRaises(PatchRejected):validate_preview(preview)

    def test_configuration_fingerprint_retains_environment_iam_and_runtime(self):
        config={'FunctionName':'fixed','CodeSha256':'old','CodeSize':123,'RevisionId':'old','LastModified':'old','Environment':{'Variables':{'PRIVATE':'value'}},'Role':'fixed-role','Runtime':'python3.13','Handler':'lambda_function.lambda_handler'}
        noise={**deepcopy(config),'CodeSha256':'new','CodeSize':456,'RevisionId':'new','LastModified':'new'}
        self.assertEqual(stable_configuration(config),stable_configuration(noise))
        for key,value in [('Environment',{'Variables':{'PRIVATE':'drift'}}),('Role','new-role'),('Runtime','python3.14'),('Handler','new.handler')]:
            changed={**deepcopy(config),key:value};self.assertNotEqual(stable_configuration(config),stable_configuration(changed))

    def test_code_revision_environment_alias_or_stack_drift_blocks_execution(self):
        baseline={'template':'unchanged','parameters':[{'ParameterKey':'private','ParameterValue':'never printed'}]}
        config={'FunctionName':'zoolanding-content-hub-prod-Function','CodeSha256':'old-code','CodeSize':123,'RevisionId':'old-revision','Environment':{'Variables':{'PRIVATE':'value'}},'State':'Active','LastUpdateStatus':'Successful'}
        record={'baselineSha256':retained.sha(baseline),'configurationSha256':retained.sha(stable_configuration(config)),'beforeCodeSha256':'old-code','beforeCodeSize':123,'beforeRevisionId':'old-revision','aliasesSha256':retained.sha([])}
        self.assertTrue(validate_live_baseline(record,baseline,config,[]))
        variants=[(baseline,{**config,'CodeSha256':'drift'},[]),(baseline,{**config,'CodeSize':456},[]),(baseline,{**config,'RevisionId':'drift'},[]),(baseline,{**config,'Environment':{'Variables':{'PRIVATE':'drift'}}},[]),(baseline,config,[{'Name':'new-alias'}]),({'template':'changed'},config,[])]
        for value in variants:
            with self.subTest(value=retained.sha(value)),self.assertRaises(PatchRejected):validate_live_baseline(record,*value)

    def test_execute_never_calls_cloudformation_when_live_code_has_drifted(self):
        self.exercise_execute(drift=True)

    def test_execute_uses_only_the_retained_native_preview_and_reads_back(self):
        self.exercise_execute(drift=False)

    def exercise_execute(self,*,drift):
        context={'headSha':'a'*40,'sourceSha':'b'*40,'sourceTree':'c'*40,'targetBaseSha':'d'*40,'mergeTree':'e'*40}
        prefix='thn/production/hub/v1-publication-date/'+context['headSha']+'/123/1/'
        def coordinate(name):return {'bucket':release.CONFIG['bucket'],'key':prefix+name,'versionId':'sealed-version','sha256':'a'*64}
        code=coordinate('candidate-code.zip');original=candidate_template(ORIGINAL,code)
        processed=deepcopy(PROCESSED);processed['Resources']['ContentHubFunction']['Properties']['Code']={'S3Bucket':code['bucket'],'S3Key':code['key'],'S3ObjectVersion':code['versionId']}
        baseline={'stackId':'fixed-stack','original':ORIGINAL,'processed':PROCESSED,'parameters':[],'resources':[],'tags':[],'roleArn':'fixed-role','terminationProtection':True}
        after={**baseline,'original':original,'processed':processed}
        config={'FunctionName':release.FUNCTION,'CodeSha256':'old-code','CodeSize':123,'RevisionId':'old-revision','State':'Active','LastUpdateStatus':'Successful','Environment':{'Variables':{'PRIVATE':'synthetic-only'}}}
        candidate_bytes=b'previously validated sealed ZIP bytes';candidate_sha=base64.b64encode(hashlib.sha256(candidate_bytes).digest()).decode()
        preview={**deepcopy(PREVIEW),'StackId':'fixed-stack','Parameters':[]}
        record={'contract':release.CONTRACT,'source':context,'baselineSha256':retained.sha(baseline),'configurationSha256':retained.sha(stable_configuration(config)),'beforeCodeSha256':'old-code','beforeCodeSize':123,'beforeRevisionId':'old-revision','aliasesSha256':retained.sha([]),'candidateCodeSha256':candidate_sha,'candidateCodeSize':len(candidate_bytes),'code':code,'changeSetArn':'fixed-change-set','stackId':'fixed-stack','createdAt':int(time.time()),'expiresAt':int(time.time())+3600,'previewSha256':retained.sha(preview),'originalSha256':retained.sha(original),'processedSha256':retained.sha(processed),'parametersSha256':retained.sha([])}
        names={'candidateTemplate':'candidate-template.json','baselineOriginal':'baseline-original.json','baselineProcessed':'baseline-processed.json','recoveryCode':'recovery/code.zip','recoveryTemplate':'recovery/template.json'}
        record.update({key:coordinate(name) for key,name in names.items()});record['digest']=retained.sha(record)
        objects={'review.json':retained.canonical(record),'candidate-code.zip':candidate_bytes,'candidate-template.json':retained.canonical(original),'baseline-original.json':retained.canonical(ORIGINAL),'baseline-processed.json':retained.canonical(PROCESSED),'recovery/code.zip':b'sealed rollback','recovery/template.json':b'sealed rollback template'}
        calls=[]
        cf=SimpleNamespace(get_template=lambda **kw:{'TemplateBody':original if kw['TemplateStage']=='Original' else processed},execute_change_set=lambda **kw:calls.append(kw),get_waiter=lambda name:SimpleNamespace(wait=lambda **kw:None))
        session=SimpleNamespace(client=lambda name:cf if name=='cloudformation' else object())
        current={**config,'CodeSha256':'drifted-code'} if drift else config
        capture=[(baseline,current,[],None),(after,{**config,'CodeSha256':candidate_sha,'CodeSize':len(candidate_bytes),'RevisionId':'new-revision'},[],None)]
        with tempfile.TemporaryDirectory() as folder,patch.dict(release.os.environ,{'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1'}),patch.object(retained,'verify_object',side_effect=lambda s3,c:objects[c['key'][len(prefix):]]),patch.object(retained,'describe_preview',return_value=preview),patch.object(release,'workflow_context',return_value=context),patch.object(release,'_capture',side_effect=capture):
            pointer=Path(folder)/'private-pointer.json';pointer.write_text(__import__('json').dumps(coordinate('review.json')))
            receipt=Path(folder)/'public-receipt.json'
            if drift:
                with self.assertRaises(PatchRejected):release.execute(session,context,pointer,receipt)
                self.assertEqual(calls,[])
            else:
                release.execute(session,context,pointer,receipt)
                self.assertEqual(calls,[{'StackName':'fixed-stack','ChangeSetName':'fixed-change-set'}])
                public=receipt.read_text();self.assertNotIn('synthetic-only',public);self.assertNotIn('fixed-role',public);self.assertNotIn(release.CONFIG['bucket'],public)

    def test_normal_workflow_keeps_graph_checks_and_has_no_broad_or_direct_deploy(self):
        workflow=(release.ROOT/'.github/workflows/deploy-production.yml').read_text()
        self.assertIn('test "$second_parent" = "$(git rev-parse refs/remotes/origin/test)"',workflow)
        self.assertIn('git merge-tree --write-tree "$first_parent" "$second_parent"',workflow)
        self.assertIn('if: needs.guard.outputs.mode == \'v1-preserve-published-at\'',workflow)
        self.assertNotIn('sam deploy',workflow)
        self.assertNotIn('update-function-code',workflow)
        self.assertIn('thn-production-retained-hub',workflow)
        with patch.dict(release.os.environ,{},clear=True),patch.object(release,'_git') as git:
            with self.assertRaises(PatchRejected):release.workflow_context()
            git.assert_not_called()


if __name__=='__main__':unittest.main()
