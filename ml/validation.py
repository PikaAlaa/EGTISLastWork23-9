"""Validation-only thresholds and source-aware reports shared by every candidate."""
import sys
from pathlib import Path
import numpy as np
from sklearn.metrics import precision_score,recall_score,f1_score,roc_auc_score
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'backend'))
from app.core.dataset_identity import dataset_identity
from evaluation.metrics import binary_metrics

def group_metrics(y,p,high):
    y=np.asarray(y,dtype=bool);p=np.asarray(p);pred=p>=high
    return {'n':len(y),'phishing_n':int(y.sum()),'legitimate_n':int((~y).sum()),
            'precision':float(precision_score(y,pred,zero_division=0)),
            'recall':float(recall_score(y,pred,zero_division=0)),
            'f1':float(f1_score(y,pred,zero_division=0)),
            'auc':float(roc_auc_score(y,p)) if len(set(y))>1 else None,
            'rates':binary_metrics(y.tolist(),pred.tolist())}

def summarize(dataset,name,y,probabilities,validation):
    if len(validation)!=len(y) or len(y)!=len(probabilities):raise ValueError('Validation rows and predictions must align')
    if not validation.split.eq('val').all():raise ValueError('Threshold selection accepts validation rows only')
    y=np.asarray(y);p=np.asarray(probabilities);candidates=[]
    for threshold in np.linspace(.3,.95,66):
        pred=p>=threshold
        precision=precision_score(y,pred,zero_division=0);recall=recall_score(y,pred,zero_division=0)
        if precision>=.9:candidates.append((recall,precision,float(threshold)))
    high=max(candidates,key=lambda x:(x[0],x[1],-x[2]))[2] if candidates else .8
    low=min(.2,float(np.quantile(p[y==1],.05))) if (y==1).any() else .2
    report={'model':name,**dataset_identity(dataset),'validation_n':len(y),**group_metrics(y,p,high),
            'low_threshold':low,'high_threshold':high,'final_test_run':False,
            'interpretation':'Pooled validation selects candidates; source mix is not representative of everyday Egyptian SMS. Sparse or single-class groups cannot establish deployment accuracy.'}
    rows=validation.reset_index(drop=True)
    for column in ['source','language','content_type']:
        report['by_'+column]={}
        for value,positions in rows.groupby(column,sort=True).indices.items():
            report['by_'+column][str(value)]=group_metrics(y[positions],p[positions],high)
    report['by_source_content_type']={}
    for (source,kind),positions in rows.groupby(['source','content_type'],sort=True).indices.items():
        report['by_source_content_type'][f'{source} / {kind}']=group_metrics(y[positions],p[positions],high)
    return report

def write_review(selection,path):
    """Publish the composition and subgroup errors beside the pooled model score."""
    lines=['# Validation composition and candidate comparison','',
        '**Development only: these results do not establish everyday Egyptian SMS accuracy.**',
        'The validation set is dominated by the translated-email source. Its labels and',
        'language tags are not proof of representative bank notifications or dialect coverage.',
        'The known invented everyday-message probes still produce false alarms.',
        'Collect representative consented messages and reserve independent groups before final testing.','',
        f"Content fingerprint: `{selection['dataset_sha256']}`",
        f"Method: `{selection['dataset_fingerprint_method']}`. All three candidates match it.",
        'This identifies CSV content across platforms; model training may still vary by runtime.','',
        f"Selected: **{selection['selected']}** using validation only. Final test: **not run**.",
        'Thresholds use pooled validation, not thresholds retuned separately for each source.','']
    for key,title in [('all','Pooled validation'),('by_source','By source'),('by_language','By language'),('by_content_type','By content type')]:
        lines += [f'## {title}','',
            '| Model | Group | N | Phishing | Legitimate | Precision | Recall | F1 | FP / legitimate |',
            '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
        for name,report in selection['candidates'].items():
            groups={'all':report} if key=='all' else report[key]
            for group,m in groups.items():
                c=m['rates']['confusion']
                precision=f"{m['precision']:.3f}" if c['tp']+c['fp'] else 'undefined'
                recall=f"{m['recall']:.3f}" if m['phishing_n'] else 'undefined'
                f1=f"{m['f1']:.3f}" if 2*c['tp']+c['fp']+c['fn'] else 'undefined'
                lines.append(f"| {name} | {group} | {m['n']} | {m['phishing_n']} | {m['legitimate_n']} | {precision} | {recall} | {f1} | {c['fp']} / {m['legitimate_n']} |")
        lines.append('')
    lines += ['Machine-readable reports in `ml/models/deployment_model.json` include confusion',
        'counts, denominators, 95% Wilson intervals, source/content-type intersections and',
        'artifact hashes. An undefined precision or recall must not be reported as evidence',
        'of success. Small groups and the existing validation source mix cannot settle deployment readiness.','']
    Path(path).write_text('\n'.join(lines),encoding='utf-8')
