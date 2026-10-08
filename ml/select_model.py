"""Compare all three candidates on the current grouped validation dataset only."""
import argparse,json,shutil,hashlib,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'backend')]
from app.core.dataset_identity import dataset_identity
from ml.validation import write_review

def checked_reports(dataset,root=ROOT):
    identity=dataset_identity(dataset);reports={}
    for name in ['char','bilstm','lightgbm']:
        path=root/f'ml/models/{name}_candidate.json'
        report=json.loads(path.read_text())
        if any(report.get(key)!=identity[key] for key in ['dataset_sha256','dataset_fingerprint_method']):
            raise ValueError(f'{name} candidate dataset differs or uses a legacy fingerprint; retrain it')
        if not all(report.get('by_'+key) for key in ['source','language','content_type']):
            raise ValueError(f'{name} candidate lacks subgroup validation')
        artifact=path.with_suffix('.keras' if name=='bilstm' else '.joblib')
        if report.get('artifact_sha256')!=hashlib.sha256(artifact.read_bytes()).hexdigest():
            raise ValueError(f'{name} artifact differs from its validation report')
        if name=='bilstm' and report.get('tokenizer_sha256')!=hashlib.sha256(path.with_suffix('.tokenizer.pkl').read_bytes()).hexdigest():
            raise ValueError('BiLSTM tokenizer differs from its validation report')
        reports[name]=report
    return identity,reports

def select(apply=False,dataset=None):
    identity,reports=checked_reports(dataset or ROOT/'data/processed/v2/dataset.csv')
    winner=max(reports,key=lambda n:(reports[n]['f1'],reports[n]['recall'],n=='char'))
    report={'selected':winner,'selection_split':'val','criterion':'highest F1 at validation-selected >=90% precision; ties favor character simplicity',
        **identity,'candidates':reports,'final_test_run':False,
        'limitations':['Pooled validation is dominated by translated emails and is not everyday-SMS accuracy','Real Egyptian SMS and final test still required','English detection remains experimental']}
    path=ROOT/'evaluation/local-results/model-selection.json';path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(report,indent=2),encoding='utf-8')
    write_review(report,ROOT/'docs/validation-by-source.md')
    if apply:
        if winner=='lightgbm':raise ValueError('LightGBM won validation; implement and test runtime support before deployment')
        env=ROOT/'.env'
        if not env.exists():raise ValueError('Initialize .env first')
        values={'ETIS_TEXT_MODEL':winner,'ETIS_TEXT_LOW_THRESHOLD':str(reports[winner]['low_threshold']),
                'ETIS_TEXT_HIGH_THRESHOLD':str(reports[winner]['high_threshold'])}
        extension='joblib' if winner=='char' else 'keras'
        source=ROOT/f'ml/models/{winner}_candidate.{extension}'
        deployed=ROOT/f'ml/models/deployed_{winner}{source.suffix}';shutil.copyfile(source,deployed)
        if winner=='bilstm':
            shutil.copyfile(source.with_suffix('.tokenizer.pkl'),ROOT/'ml/models/deployed_bilstm.tokenizer.pkl')
            values.update(ETIS_BILSTM_MODEL_PATH='ml/models/deployed_bilstm.keras',ETIS_BILSTM_TOKENIZER_PATH='ml/models/deployed_bilstm.tokenizer.pkl')
        else:values['ETIS_CHAR_MODEL_PATH']='ml/models/deployed_char.joblib'
        deployment={**report,'artifact_sha256':hashlib.sha256(deployed.read_bytes()).hexdigest(),'status':'experimental; sealed real-data evaluation pending'}
        (ROOT/'ml/models/deployment_model.json').write_text(json.dumps(deployment,indent=2),encoding='utf-8')
        lines=env.read_text().splitlines();updated=[]
        for line in lines:
            key=line.split('=',1)[0]
            updated.append(key+'='+values.pop(key) if key in values else line)
        updated.extend(k+'='+v for k,v in values.items());env.write_text('\n'.join(updated)+'\n',encoding='utf-8')
    return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--apply-local',action='store_true');p.add_argument('--dataset');a=p.parse_args();print(json.dumps(select(a.apply_local,a.dataset),indent=2))
