"""Wilson intervals for proportions; every estimate records its denominator."""
import math
def proportion(successes,total):
    if not total:return {'value':None,'n':0,'ci95':[None,None]}
    p=successes/total;z=1.959963984540054;denom=1+z*z/total
    center=(p+z*z/(2*total))/denom;radius=z*math.sqrt(p*(1-p)/total+z*z/(4*total*total))/denom
    return {'value':p,'n':total,'ci95':[max(0,center-radius),min(1,center+radius)]}
def binary_metrics(labels,predictions):
    tp=sum(y and p for y,p in zip(labels,predictions));fp=sum(not y and p for y,p in zip(labels,predictions))
    fn=sum(y and not p for y,p in zip(labels,predictions));tn=sum(not y and not p for y,p in zip(labels,predictions))
    return {'precision':proportion(tp,tp+fp),'recall':proportion(tp,tp+fn),'false_positive_rate':proportion(fp,fp+tn),
        'confusion':{'tp':tp,'fp':fp,'fn':fn,'tn':tn}}
