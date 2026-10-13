"""Download ONLY approved PhreshPhish column chunks, never whole upstream Parquet files.

An explicit HTTP range reader rejects full-body responses before reading them.
Parquet footer metadata locates the five allowed columns; all other data chunks
are absent from the virtual file. No destination URL is ever requested.
The lock records upstream-declared file SHA-256 plus independently measured
hashes of each selected byte range and each local five-column projection.
"""
import argparse,hashlib,io,json,struct,sys,time
from concurrent.futures import ThreadPoolExecutor,as_completed
from datetime import datetime,timezone
from pathlib import Path
import requests
import pyarrow as pa
import pyarrow.parquet as pq
ROOT=Path(__file__).resolve().parents[2]
DATASET='phreshphish/phreshphish'
REVISION='eabec4b7a66324b79cc8a0ad856d1731dc26fe1a'
COLUMNS=['url','label','target','date','lang']
OUT=ROOT/'data/external/phreshphish'
REPORT=ROOT/'evaluation/reports/2026-10-v3/phreshphish'
LOCK=ROOT/'data/phreshphish-lock.json'

def sha(data):return hashlib.sha256(data).hexdigest()

def range_get(session,url,start,end,size):
    # end is exclusive. Never consume a server response that ignored our range.
    for attempt in range(4):
        with session.get(url,headers={'Range':f'bytes={start}-{end-1}','Accept-Encoding':'identity'},stream=True,timeout=(20,90)) as response:
            if response.status_code in (429,500,502,503,504) and attempt<3:
                time.sleep(2**attempt);continue
            if response.status_code!=206 or response.headers.get('Content-Range')!=f'bytes {start}-{end-1}/{size}':
                raise RuntimeError(f'Range request not honoured: HTTP {response.status_code}; body NOT read')
            data=response.raw.read(end-start)
            if len(data)!=end-start:raise IOError('Truncated selected-column byte range')
            return data
    raise IOError('Range request retries exhausted')

def merge_ranges(ranges):
    merged=[]
    for start,end in sorted(ranges):
        if merged and start==merged[-1][1]:merged[-1]=(merged[-1][0],end)
        elif merged and start<merged[-1][1]:raise ValueError('Overlapping column chunks')
        else:merged.append((start,end))
    return merged

class ProjectedFile(io.RawIOBase):
    """Sparse in-memory view: zero padding where unselected columns would be."""
    def __init__(self,size,segments):super().__init__();self.size=size;self.segments=segments;self.pos=0
    def readable(self):return True
    def seekable(self):return True
    def tell(self):return self.pos
    def seek(self,offset,whence=0):
        pos=offset if whence==0 else self.pos+offset if whence==1 else self.size+offset
        if pos<0:raise ValueError('negative seek')
        self.pos=pos;return pos
    def read(self,n=-1):
        if n<0:raise ValueError('Unbounded reads forbidden')
        end=min(self.size,self.pos+n)
        if end<=self.pos:return b''
        if end-self.pos>64*1024*1024:raise ValueError('Unexpected oversized read')
        result=bytearray(end-self.pos)
        for start,data in self.segments:
            a=max(start,self.pos);b=min(start+len(data),end)
            if a<b:result[a-self.pos:b-self.pos]=data[a-start:b-start]
        self.pos=end;return bytes(result)

def project_file(info,expected=None,output=OUT):
    filename=info['rfilename'];size=info['size'];url=f'https://huggingface.co/datasets/{DATASET}/resolve/{REVISION}/{filename}'
    target=output/Path(filename).name
    if target.exists() and expected:
        if sha(target.read_bytes())!=expected['projected_sha256']:raise ValueError(f'Local checksum mismatch: {target.name}')
        if pq.read_schema(target).names!=COLUMNS:raise ValueError('Unexpected local columns')
        return expected
    with requests.Session() as session:
        tail=range_get(session,url,size-8,size,size)
        if tail[-4:]!=b'PAR1':raise ValueError('Unsupported Parquet footer')
        count=struct.unpack('<I',tail[:4])[0]
        if not 0<count<16*1024*1024:raise ValueError('Unreasonable metadata length')
        footer_start=size-8-count;footer=range_get(session,url,footer_start,size-8,size)
        # Only parse schema/offsets; never render or serialize column statistics.
        metadata=pq.read_metadata(pa.BufferReader(b'PAR1'+footer+tail))
        schema=metadata.schema.to_arrow_schema();assert all(c in schema.names for c in COLUMNS)
        allowed=[];blocked=[]
        for g in range(metadata.num_row_groups):
            rg=metadata.row_group(g)
            for i in range(rg.num_columns):
                column=rg.column(i);start=min(x for x in [column.dictionary_page_offset,column.data_page_offset] if x is not None and x>=0)
                pair=(start,start+column.total_compressed_size)
                (allowed if column.path_in_schema in COLUMNS else blocked).append(pair)
        ranges=merge_ranges(allowed)
        assert all(b<=c or a>=d for a,b in ranges for c,d in blocked)
        segments=[(0,b'PAR1'),(footer_start,footer+tail)];range_records=[]
        for start,end in ranges:
            data=range_get(session,url,start,end,size);segments.append((start,data))
            range_records.append({'start':start,'end_exclusive':end,'sha256':sha(data)})
        record={'upstream_file':filename,'upstream_bytes':size,'upstream_declared_sha256':info['lfs']['sha256'],
          'upstream_whole_file_downloaded':False,'upstream_whole_file_hash_locally_verified':False,
          'footer_sha256':sha(footer+tail),'selected_ranges':range_records,'columns':COLUMNS,
          'downloaded_at_utc':datetime.now(timezone.utc).isoformat(),'rows':metadata.num_rows}
        if expected:
            for field in ['upstream_declared_sha256','footer_sha256','selected_ranges','columns','rows']:
                if record[field]!=expected[field]:raise ValueError(f'Pinned source checksum/metadata differs: {filename} / {field}')
        view=ProjectedFile(size,segments)
        table=pq.ParquetFile(view,metadata=metadata,pre_buffer=False).read(columns=COLUMNS,use_threads=False)
        assert table.column_names==COLUMNS
        table=table.replace_schema_metadata(None)
        sink=pa.BufferOutputStream();pq.write_table(table,sink,compression='zstd',version='2.6',row_group_size=65536)
        payload=sink.getvalue().to_pybytes();record['projected_sha256']=sha(payload);record['projected_bytes']=len(payload)
        if expected and record['projected_sha256']!=expected['projected_sha256']:raise ValueError('Projected file checksum differs; use pinned PyArrow version')
        output.mkdir(parents=True,exist_ok=True)
        if target.exists():
            if target.read_bytes()!=payload:raise ValueError('Refusing to replace differing local projection')
        else:
            with target.open('xb') as f:f.write(payload)
        return record

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--record-lock',action='store_true',help='First acquisition: record actual range and projection hashes; does not overwrite an existing lock')
    parser.add_argument('--limit',type=int,help='Access check only; never produces a complete-dataset lock')
    parser.add_argument('--workers',type=int,default=4);args=parser.parse_args()
    if LOCK.exists() and args.record_lock:raise ValueError('Lock already exists; normal reruns verify it')
    if not LOCK.exists() and not args.record_lock:raise ValueError('No pinned lock; initial audited acquisition requires --record-lock')
    expected=json.loads(LOCK.read_text()) if LOCK.exists() else None
    r=requests.get(f'https://huggingface.co/api/datasets/{DATASET}/revision/{REVISION}',params={'blobs':'true'},timeout=60);r.raise_for_status();meta=r.json()
    if meta['sha']!=REVISION:raise ValueError('Revision mismatch')
    files=[f for f in meta['siblings'] if f['rfilename'].startswith(('data/train-','data/test-')) and f['rfilename'].endswith('.parquet')]
    files=sorted(files,key=lambda f:f['rfilename']);files=files[:args.limit] if args.limit else files
    byname={e['upstream_file']:e for e in expected['files']} if expected else {}
    if expected and not args.limit and {f['rfilename'] for f in files}!=set(byname):raise ValueError('Pinned upstream file set differs')
    if expected:
        for f in files:
            if f['lfs']['sha256']!=byname[f['rfilename']]['upstream_declared_sha256']:raise ValueError('Upstream declared file checksum differs')
    records=[]
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            pending={pool.submit(project_file,f,byname.get(f['rfilename'])):f for f in files}
            for future in as_completed(pending):
                record=future.result();records.append(record)
                print(f"Projected {record['upstream_file']}: {record['rows']} rows; {record['projected_bytes']} bytes; five allowed columns",flush=True)
    except Exception as exc:
        print('DOWNLOAD STOPPED:',str(exc),file=sys.stderr);raise
    result={'dataset':DATASET,'revision':REVISION,'card_version':'1.0.1 (2026-02-07)','download_date':datetime.now(timezone.utc).date().isoformat(),
      'complete':not bool(args.limit),'columns':COLUMNS,'html_column_downloaded_decoded_or_stored':False,
      'hash_scope':'Upstream whole-file hashes declared by Hugging Face; verified local SHA-256 for selected source ranges and five-column projections only.',
      'licence':'CC BY 4.0; card additionally requests anti-phishing research use only','files':sorted(records,key=lambda r:r['upstream_file']),
      'data_sha256':sha(json.dumps(sorted([(r['upstream_file'],r['projected_sha256']) for r in records])).encode()),
      'model_sha256':None,'libraries':{'pyarrow':pa.__version__,'requests':requests.__version__}}
    if not args.limit and not expected:LOCK.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    REPORT.mkdir(exist_ok=True,parents=True)
    (REPORT/('download_access_check.json' if args.limit else 'download.json')).write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print('COMPLETE' if result['complete'] else 'ACCESS CHECK ONLY',len(records),'projected files')

if __name__=='__main__':main()
