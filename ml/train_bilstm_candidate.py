"""Train a separate BiLSTM using grouped v2 training data. Never reads test rows for evaluation."""
import argparse,json,hashlib,pickle,sys,os
os.environ.setdefault('TF_CPP_MIN_LOG_LEVEL','2')
from pathlib import Path
import numpy as np,pandas as pd
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'backend'))
from app.core.text_utils import normalize_arabic_text,text_windows
from ml.validation import summarize
def train(dataset,output,epochs=20):
    import tensorflow as tf
    from tensorflow.keras.preprocessing.text import Tokenizer
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    tf.config.threading.set_inter_op_parallelism_threads(2);tf.config.threading.set_intra_op_parallelism_threads(2)
    tf.keras.utils.set_random_seed(42)
    d=pd.read_csv(dataset,low_memory=False).fillna('');d=d[d.content_type.isin(['text','email'])]
    tr=d[d.split=='train'];val=d[d.split=='val']
    if tr.empty or val.empty:raise ValueError('Training and validation data required')
    expand=lambda df:([(normalize_arabic_text(w),int(row.label=='phishing')) for row in df.itertuples() for w in text_windows(row.text)])
    training=expand(tr);validation=expand(val)
    tokenizer=Tokenizer(num_words=5000,oov_token='<OOV>');tokenizer.fit_on_texts([s for s,_ in training])
    encode=lambda strings:pad_sequences(tokenizer.texts_to_sequences(strings),maxlen=200,padding='post',truncating='post')
    x=encode([s for s,_ in training]);y=np.array([v for _,v in training])
    vx=encode([s for s,_ in validation]);vy=np.array([v for _,v in validation])
    model=tf.keras.Sequential([tf.keras.layers.Input((200,)),tf.keras.layers.Embedding(5000,32,mask_zero=True),
        tf.keras.layers.Bidirectional(tf.keras.layers.LSTM(16,dropout=.3,recurrent_dropout=.2)),tf.keras.layers.Dropout(.4),
        tf.keras.layers.Dense(8,activation='relu',kernel_regularizer=tf.keras.regularizers.l2(.001)),tf.keras.layers.Dense(1,activation='sigmoid')])
    model.compile(optimizer='adam',loss='binary_crossentropy',metrics=['accuracy'])
    # Explicit bounded tf.data pools avoid using all CPU cores on a developer's computer.
    options=tf.data.Options();options.threading.private_threadpool_size=2
    ds=tf.data.Dataset.from_tensor_slices((x,y)).shuffle(len(y),seed=42).batch(64).with_options(options)
    vd=tf.data.Dataset.from_tensor_slices((vx,vy)).batch(64).with_options(options)
    weights={int(c):float(len(y)/(2*(y==c).sum())) for c in np.unique(y)}
    model.fit(ds,validation_data=vd,epochs=epochs,class_weight=weights,
        callbacks=[tf.keras.callbacks.EarlyStopping(monitor='val_loss',patience=3,restore_best_weights=True)],verbose=2)
    windows=[];boundaries=[]
    for text in val.text:
        start=len(windows);windows.extend(normalize_arabic_text(w) for w in text_windows(text));boundaries.append((start,len(windows)))
    infer=tf.function(lambda batch:model(batch,training=False),reduce_retracing=True)
    encoded=encode(windows)
    scores=np.concatenate([infer(encoded[start:start+128]).numpy().ravel() for start in range(0,len(encoded),128)])
    probabilities=[float(scores[start:end].max()) for start,end in boundaries]
    report=summarize(Path(dataset),'bilstm_candidate',(val.label=='phishing').astype(int),probabilities,val)
    report['parameters']={'vocabulary':5000,'embedding':32,'lstm_units':16,'seed':42,'epochs_max':epochs,'window_words':150,'stride':75}
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True);model.save(output)
    with output.with_suffix('.tokenizer.pkl').open('wb') as f:pickle.dump(tokenizer,f)
    report['artifact_sha256']=hashlib.sha256(output.read_bytes()).hexdigest()
    report['tokenizer_sha256']=hashlib.sha256(output.with_suffix('.tokenizer.pkl').read_bytes()).hexdigest()
    output.with_suffix('.json').write_text(json.dumps(report,indent=2),encoding='utf-8');return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--dataset',default=str(ROOT/'data/processed/v2/dataset.csv'))
    p.add_argument('--output',default=str(ROOT/'ml/models/bilstm_candidate.keras'));p.add_argument('--epochs',type=int,default=20)
    a=p.parse_args();print(json.dumps(train(a.dataset,a.output,a.epochs),indent=2))
