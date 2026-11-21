"""Native, retained, code-only release of the exact first-publication-date fix.

No SAM deploy, Lambda update API, environment update, IAM mutation or V2 operation
is permitted here. Only an existing CloudFormation Code property may change.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import time
import urllib.request
from urllib.parse import quote,urlsplit
import zipfile

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from tools import thn_production_release as retained
from tools.thn_production_service import CONFIG
from tools.v1_publication_date_patch import PatchRejected,require,validate_publish_date_change
from tools.classify_production_promotion import classify_selection,git_patch_documents,PromotionSelectionError

STACK='zoolanding-content-hub-prod'
FUNCTION='zoolanding-content-hub-prod-Function'
LOGICAL='ContentHubFunction'
MODE='v1-preserve-published-at'
CONTRACT='zoolanding-v1-publication-date-release/v1'


def patch_deployed_zip(body,base_source,candidate_source):
    require(isinstance(body,bytes) and len(body)<=50*1024*1024,'v1_zip_size_invalid')
    validate_publish_date_change(base_source.decode('utf-8'),candidate_source.decode('utf-8'))
    result=io.BytesIO()
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as old,zipfile.ZipFile(result,'w') as new:
            names=old.namelist();require(len(names)==len(set(names)) and names.count('lambda_function.py')==1,'v1_zip_inventory_invalid')
            forbidden={p.name for p in ROOT.glob('*.py')}-{'lambda_function.py'}
            require(sum(i.file_size for i in old.infolist())<=250*1024*1024,'v1_zip_expansion_invalid')
            for info in old.infolist():
                pure=PurePosixPath(info.filename)
                require(not pure.is_absolute() and '..' not in pure.parts and '\\' not in info.filename and not re.match(r'^[A-Za-z]:',info.filename),'v1_zip_path_invalid')
                require(not stat.S_ISLNK(info.external_attr>>16) and not(info.flag_bits&1),'v1_zip_entry_invalid')
                require(pure.name not in forbidden and pure.parts[0] not in {'.git','.github','tests','tools','changelog','docs'},'v1_zip_cross_function_source')
                content=old.read(info)
                if info.filename=='lambda_function.py':
                    require(content.replace(b'\r\n',b'\n')==base_source.replace(b'\r\n',b'\n'),'v1_deployed_source_drift')
                    content=candidate_source
                new.writestr(deepcopy(info),content)
            new.comment=old.comment
        with zipfile.ZipFile(io.BytesIO(body)) as old,zipfile.ZipFile(io.BytesIO(result.getvalue())) as new:
            require(old.namelist()==new.namelist())
            require(all(old.read(n)==new.read(n) for n in old.namelist() if n!='lambda_function.py'),'v1_dependency_bytes_changed')
        return result.getvalue()
    except (zipfile.BadZipFile,UnicodeError,KeyError):
        raise PatchRejected('v1_zip_invalid') from None


def _code(code):
    require(isinstance(code,dict) and set(code)=={'bucket','key','versionId','sha256'})
    require(all(isinstance(code[k],str) and code[k] for k in code) and code['versionId']!='null')
    require(bool(re.fullmatch('[a-f0-9]{64}',code['sha256'])))
    return {'S3Bucket':code['bucket'],'S3Key':code['key'],'S3ObjectVersion':code['versionId']}


def candidate_template(before,code):
    result=deepcopy(before);item=result.get('Resources',{}).get(LOGICAL,{})
    require(item.get('Type') in {'AWS::Serverless::Function','AWS::Lambda::Function'},'v1_function_resource_missing')
    properties=item.get('Properties',{});native=_code(code)
    if item['Type']=='AWS::Serverless::Function':
        require('CodeUri' in properties);properties['CodeUri']={'Bucket':native['S3Bucket'],'Key':native['S3Key'],'Version':native['S3ObjectVersion']}
    else:
        require('Code' in properties);properties['Code']=native
    return result


def validate_templates(before_original,before_processed,after_original,after_processed,code):
    require(after_original==candidate_template(before_original,code),'v1_original_template_noncode_change')
    expected=deepcopy(before_processed);item=expected.get('Resources',{}).get(LOGICAL,{})
    require(item.get('Type')=='AWS::Lambda::Function' and 'Code' in item.get('Properties',{}),'v1_processed_function_missing')
    item['Properties']['Code']=_code(code)
    require(after_processed==expected,'v1_processed_template_noncode_change')
    return True


def validate_preview(preview):
    require(preview.get('Status')=='CREATE_COMPLETE' and preview.get('ExecutionStatus')=='AVAILABLE','v1_preview_unavailable')
    changes=preview.get('Changes');require(isinstance(changes,list) and len(changes)==1,'v1_preview_resource_inventory')
    resource=changes[0].get('ResourceChange',{})
    require(resource.get('Action')=='Modify' and resource.get('LogicalResourceId')==LOGICAL and resource.get('PhysicalResourceId')==FUNCTION and resource.get('ResourceType')=='AWS::Lambda::Function' and resource.get('Replacement')=='False' and resource.get('Scope')==['Properties'],'v1_preview_resource_boundary')
    details=resource.get('Details');require(isinstance(details,list) and bool(details),'v1_preview_details_missing')
    for detail in details:
        target=detail.get('Target',{})
        require(detail.get('ChangeSource')=='DirectModification' and detail.get('Evaluation')=='Static' and target.get('Attribute')=='Properties' and target.get('Name')=='Code' and target.get('RequiresRecreation')=='Never','v1_preview_property_boundary')
    return True


def stable_configuration(value):
    volatile={'CodeSha256','CodeSize','RevisionId','LastModified','LastUpdateStatus','LastUpdateStatusReason','LastUpdateStatusReasonCode','State','StateReason','StateReasonCode','ResponseMetadata'}
    return {k:v for k,v in value.items() if k not in volatile}


def validate_live_baseline(record,baseline,configuration,aliases):
    require(retained.sha(baseline)==record['baselineSha256'],'v1_stack_drift')
    require(configuration.get('FunctionName')==FUNCTION and configuration.get('State')=='Active' and configuration.get('LastUpdateStatus')=='Successful','v1_function_unavailable')
    require(configuration.get('CodeSha256')==record['beforeCodeSha256'] and configuration.get('RevisionId')==record['beforeRevisionId'],'v1_code_or_revision_drift')
    require(configuration.get('CodeSize')==record['beforeCodeSize'],'v1_code_size_drift')
    require(retained.sha(stable_configuration(configuration))==record['configurationSha256'],'v1_configuration_drift')
    require(retained.sha(aliases)==record['aliasesSha256'],'v1_alias_drift')
    return True


def _git(*args):
    value=subprocess.run(['git',*args],cwd=ROOT,capture_output=True,text=True)
    require(value.returncode==0,'v1_git_authority_unavailable')
    return value.stdout.strip()


def workflow_context():
    """Production execution is available only inside the normal protected workflow."""
    require(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_EVENT_NAME')=='push' and os.environ.get('GITHUB_REF')=='refs/heads/main','v1_normal_workflow_required')
    require(os.environ.get('GITHUB_REPOSITORY')=='LynxPardelle/zoolanding-content-hub' and os.environ.get('GITHUB_WORKFLOW_REF')=='LynxPardelle/zoolanding-content-hub/.github/workflows/deploy-production.yml@refs/heads/main','v1_workflow_identity_invalid')
    require(os.environ.get('PUSH_FORCED')=='false','v1_forced_or_unknown_push')
    head=_git('rev-parse','HEAD');require(head==os.environ.get('GITHUB_SHA') and re.fullmatch('[a-f0-9]{40}',head),'v1_head_mismatch')
    parents=_git('rev-list','--parents','-n','1','HEAD').split();require(len(parents)==3 and parents[0]==head and parents[1]==os.environ.get('BEFORE_SHA'),'v1_promotion_graph_invalid')
    refs=dict((line.split()[1],line.split()[0]) for line in _git('ls-remote','--heads','origin','main','test').splitlines())
    require(refs.get('refs/heads/main')==head and refs.get('refs/heads/test')==parents[2],'v1_source_authority_drift')
    context=dict(sourceSha=parents[2],sourceTree=_git('rev-parse',parents[2]+'^{tree}'),targetBaseSha=parents[1],mergeTree=_git('rev-parse','HEAD^{tree}'))
    require(_git('merge-tree','--write-tree',parents[1],parents[2])==context['mergeTree'],'v1_merge_tree_mismatch')
    mode=classify_selection(os.environ.get('PRODUCTION_PROMOTION_SELECTION_JSON'),**context,v1_documents=git_patch_documents(context['targetBaseSha'],context['mergeTree']))
    require(mode==MODE,'v1_release_mode_invalid')
    require(all(re.fullmatch('[1-9][0-9]*',os.environ.get(key,'')) for key in ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT')),'v1_run_identity_invalid')
    return {**context,'headSha':head}


def _prefix(context):
    return f'thn/production/hub/v1-publication-date/{context["headSha"]}/{os.environ["GITHUB_RUN_ID"]}/{os.environ["GITHUB_RUN_ATTEMPT"]}/'


def _capture(session):
    require(session.client('sts').get_caller_identity()['Account']==retained.ACCOUNT,'v1_account_mismatch')
    baseline=retained.snapshot(session.client('cloudformation'),STACK)
    require(baseline['status'] in {'CREATE_COMPLETE','UPDATE_COMPLETE','UPDATE_ROLLBACK_COMPLETE','IMPORT_COMPLETE'},'v1_existing_stable_stack_required')
    resources=[r for r in baseline['resources'] if r.get('LogicalResourceId')==LOGICAL]
    require(len(resources)==1 and resources[0].get('PhysicalResourceId')==FUNCTION and resources[0].get('ResourceType')=='AWS::Lambda::Function','v1_physical_function_mismatch')
    function=session.client('lambda').get_function(FunctionName=FUNCTION)
    configuration=function['Configuration']
    require(configuration.get('Version')=='$LATEST' and configuration.get('PackageType')=='Zip' and configuration.get('Handler')=='lambda_function.lambda_handler','v1_function_kind_mismatch')
    aliases=session.client('lambda').list_aliases(FunctionName=FUNCTION).get('Aliases',[])
    require(not aliases,'v1_aliases_not_supported')
    return baseline,configuration,aliases,function['Code']['Location']


def _download_code(location):
    parsed=urlsplit(location)
    require(parsed.scheme=='https' and parsed.hostname and parsed.hostname.endswith('.amazonaws.com'),'v1_code_download_origin_invalid')
    with urllib.request.urlopen(location,timeout=45) as response:
        value=response.read(50*1024*1024+1)
    require(len(value)<=50*1024*1024,'v1_code_download_too_large')
    return value


def _parameters(parameters):
    require(isinstance(parameters,list) and len({p['ParameterKey'] for p in parameters})==len(parameters),'v1_parameter_inventory_invalid')
    return sorted([{k:p[k] for k in ('ParameterKey','ParameterValue','ResolvedValue') if k in p} for p in parameters],key=lambda p:p['ParameterKey'])


def _url(coordinate):
    return f'https://{coordinate["bucket"]}.s3.{retained.REGION}.amazonaws.com/{quote(coordinate["key"])}?versionId={quote(coordinate["versionId"])}'


def _safe_receipt(record,status):
    return {'contract':CONTRACT,'status':status,'sourceSha':record['source']['headSha'],'targetFunction':FUNCTION,'changedProperties':['Code'],'changedRuntimeFiles':['lambda_function.py'],'beforeCodeSha256':record['beforeCodeSha256'],'candidateCodeSha256':record['candidateCodeSha256'],'nativeInventorySha256':record['previewSha256'],'reviewDigest':record['digest'],'rollbackSealed':True,'v2Changed':False,'infrastructureChanged':False,'environmentChanged':False,'publishedAtPolicy':'preserve original; use current timestamp only on first publication'}


def prepare(session,context,pointer_file,receipt_file):
    cf=session.client('cloudformation');s3=session.client('s3')
    baseline,configuration,aliases,location=_capture(session)
    original=retained.parse_template(baseline['original']);processed=retained.parse_template(baseline['processed'])
    body=_download_code(location)
    require(base64.b64encode(hashlib.sha256(body).digest()).decode()==configuration['CodeSha256'],'v1_download_checksum_mismatch')
    require(configuration.get('CodeSize')==len(body),'v1_download_size_mismatch')
    base_source=subprocess.check_output(['git','show',context['targetBaseSha']+':lambda_function.py'],cwd=ROOT)
    candidate_source=(ROOT/'lambda_function.py').read_bytes()
    patched=patch_deployed_zip(body,base_source,candidate_source)
    # Reuse the existing function-boundary artifact check; no new build/dependencies enter the ZIP.
    from tools.check_lambda_artifacts import validate_artifact
    import tempfile
    with tempfile.TemporaryDirectory() as folder:
        with zipfile.ZipFile(io.BytesIO(patched)) as archive:archive.extractall(folder)
        validate_artifact(LOGICAL,folder)
    prefix=_prefix(context);bucket=CONFIG['bucket']
    recovery_code=retained.seal_object(s3,bucket,prefix+'recovery/code.zip',body)
    recovery_template=retained.seal_object(s3,bucket,prefix+'recovery/template.json',retained.canonical(candidate_template(original,recovery_code)))
    before_original=retained.seal_object(s3,bucket,prefix+'baseline-original.json',retained.canonical(original))
    before_processed=retained.seal_object(s3,bucket,prefix+'baseline-processed.json',retained.canonical(processed))
    code=retained.seal_object(s3,bucket,prefix+'candidate-code.zip',patched)
    candidate=candidate_template(original,code)
    template=retained.seal_object(s3,bucket,prefix+'candidate-template.json',retained.canonical(candidate))
    request=dict(StackName=STACK,ChangeSetName='v1-publication-date-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT'],ChangeSetType='UPDATE',TemplateURL=_url(template),Parameters=[{'ParameterKey':p['ParameterKey'],'UsePreviousValue':True} for p in baseline['parameters']],Capabilities=['CAPABILITY_NAMED_IAM','CAPABILITY_AUTO_EXPAND'],Tags=baseline['tags'],Description='Preserve article publication dates; existing v1 Lambda code only')
    if baseline.get('roleArn'):request['RoleARN']=baseline['roleArn']
    # Reject code/config/stack/source drift before creating even the retained preview.
    created_at=int(time.time())
    record={'contract':CONTRACT,'source':context,'baselineSha256':retained.sha(baseline),'configurationSha256':retained.sha(stable_configuration(configuration)),'beforeCodeSha256':configuration['CodeSha256'],'beforeCodeSize':configuration['CodeSize'],'beforeRevisionId':configuration['RevisionId'],'aliasesSha256':retained.sha(aliases),'candidateCodeSha256':base64.b64encode(hashlib.sha256(patched).digest()).decode(),'candidateCodeSize':len(patched),'code':code,'candidateTemplate':template,'baselineOriginal':before_original,'baselineProcessed':before_processed,'recoveryCode':recovery_code,'recoveryTemplate':recovery_template,'stackId':baseline['stackId'],'createdAt':created_at,'expiresAt':created_at+3600}
    fresh,config,alias,_=_capture(session);validate_live_baseline(record,fresh,config,alias);require(workflow_context()==context,'v1_source_changed_before_preview')
    arn=cf.create_change_set(**request)['Id']
    cf.get_waiter('change_set_create_complete').wait(ChangeSetName=arn)
    preview=retained.describe_preview(cf,arn);validate_preview(preview)
    after_original=retained.parse_template(cf.get_template(ChangeSetName=arn,TemplateStage='Original')['TemplateBody'])
    after_processed=retained.parse_template(cf.get_template(ChangeSetName=arn,TemplateStage='Processed')['TemplateBody'])
    validate_templates(original,processed,after_original,after_processed,code)
    require(preview['StackId']==baseline['stackId'] and _parameters(preview.get('Parameters',[]))==_parameters(baseline['parameters']),'v1_preview_parameters_changed')
    record.update(changeSetArn=arn,previewSha256=retained.sha(preview),originalSha256=retained.sha(after_original),processedSha256=retained.sha(after_processed),parametersSha256=retained.sha(_parameters(preview.get('Parameters',[]))))
    record['digest']=retained.sha(record)
    sealed=retained.seal_object(s3,bucket,prefix+'review.json',retained.canonical(record))
    Path(pointer_file).write_text(json.dumps(sealed),encoding='utf-8')
    Path(receipt_file).write_text(json.dumps(_safe_receipt(record,'prepared'),indent=2)+'\n',encoding='utf-8')
    return record


def execute(session,context,pointer_file,receipt_file):
    cf=session.client('cloudformation');s3=session.client('s3')
    pointer=json.loads(Path(pointer_file).read_text(encoding='utf-8'))
    require(pointer.get('bucket')==CONFIG['bucket'] and pointer.get('key')==_prefix(context)+'review.json','v1_review_pointer_scope_invalid')
    record=json.loads(retained.verify_object(s3,pointer))
    require(record.get('contract')==CONTRACT and record.get('source')==context and record.get('digest')==retained.sha({k:v for k,v in record.items() if k!='digest'}),'v1_review_integrity_invalid')
    require(type(record['createdAt']) is int and record['createdAt']<=int(time.time())<record['expiresAt'] and record['expiresAt']-record['createdAt']==3600,'v1_review_expired')
    expected_names={'code':'candidate-code.zip','candidateTemplate':'candidate-template.json','baselineOriginal':'baseline-original.json','baselineProcessed':'baseline-processed.json','recoveryCode':'recovery/code.zip','recoveryTemplate':'recovery/template.json'}
    require(all(record[key].get('bucket')==CONFIG['bucket'] and record[key].get('key')==_prefix(context)+name for key,name in expected_names.items()),'v1_retained_object_scope_invalid')
    objects={key:retained.verify_object(s3,record[key]) for key in ('code','candidateTemplate','baselineOriginal','baselineProcessed','recoveryCode','recoveryTemplate')}
    require(base64.b64encode(hashlib.sha256(objects['code']).digest()).decode()==record['candidateCodeSha256'],'v1_candidate_checksum_mismatch')
    require(len(objects['code'])==record['candidateCodeSize'],'v1_candidate_size_mismatch')
    preview=retained.describe_preview(cf,record['changeSetArn']);validate_preview(preview)
    require(preview['StackId']==record['stackId'] and retained.sha(preview)==record['previewSha256'],'v1_native_preview_drift')
    original=retained.parse_template(cf.get_template(ChangeSetName=record['changeSetArn'],TemplateStage='Original')['TemplateBody'])
    processed=retained.parse_template(cf.get_template(ChangeSetName=record['changeSetArn'],TemplateStage='Processed')['TemplateBody'])
    validate_templates(json.loads(objects['baselineOriginal']),json.loads(objects['baselineProcessed']),original,processed,record['code'])
    require(retained.sha(original)==record['originalSha256'] and retained.sha(processed)==record['processedSha256'] and retained.sha(_parameters(preview.get('Parameters',[])))==record['parametersSha256'],'v1_preview_content_drift')
    require(workflow_context()==context,'v1_source_changed_before_execution')
    baseline,configuration,aliases,_=_capture(session);validate_live_baseline(record,baseline,configuration,aliases)
    # Only execution mutation: one already reviewed native Code-only change set.
    cf.execute_change_set(StackName=record['stackId'],ChangeSetName=record['changeSetArn'])
    cf.get_waiter('stack_update_complete').wait(StackName=record['stackId'])
    after,config,aliases,_=_capture(session)
    require(config.get('CodeSize')==record['candidateCodeSize'],'v1_postrelease_code_size_mismatch')
    require(config['CodeSha256']==record['candidateCodeSha256'] and retained.sha(stable_configuration(config))==record['configurationSha256'] and retained.sha(aliases)==record['aliasesSha256'],'v1_postrelease_configuration_mismatch')
    validate_templates(json.loads(objects['baselineOriginal']),json.loads(objects['baselineProcessed']),retained.parse_template(after['original']),retained.parse_template(after['processed']),record['code'])
    require(_parameters(after['parameters'])==_parameters(baseline['parameters']),'v1_postrelease_parameter_mismatch')
    before_ids={(r['LogicalResourceId'],r['PhysicalResourceId'],r['ResourceType']) for r in baseline['resources']}
    after_ids={(r['LogicalResourceId'],r['PhysicalResourceId'],r['ResourceType']) for r in after['resources']}
    require(before_ids==after_ids and after['tags']==baseline['tags'] and after['roleArn']==baseline['roleArn'] and after['terminationProtection']==baseline['terminationProtection'],'v1_postrelease_stack_identity_mismatch')
    Path(receipt_file).write_text(json.dumps(_safe_receipt(record,'executed'),indent=2)+'\n',encoding='utf-8')
    return record


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=['check','prepare','execute'])
    parser.add_argument('--pointer');parser.add_argument('--receipt')
    args=parser.parse_args()
    try:
        context=workflow_context()
        if args.operation=='check':print('v1_exact_date_patch_source_verified');return 0
        require(args.pointer and args.receipt,'v1_internal_receipt_paths_required')
        import boto3
        session=boto3.Session(region_name=retained.REGION)
        (prepare if args.operation=='prepare' else execute)(session,context,args.pointer,args.receipt)
        print('v1_native_code_only_'+args.operation+'_verified')
        return 0
    except (PatchRejected,PromotionSelectionError,retained.ReleaseError) as error:
        print(str(error),file=sys.stderr);return 2
    except Exception:
        # SDK/HTTP exceptions may embed URLs or parameters. Keep provider details private.
        print('v1_provider_operation_failed; no provider values were logged',file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
