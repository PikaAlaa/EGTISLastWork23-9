import datetime,json,os,pathlib,platform,re,shutil,subprocess,sys,time
root=pathlib.Path(__file__).resolve().parents[1]
stage=sys.argv[1]
out=root/'evaluation/reports/2026-10-v4'
out.mkdir(parents=True,exist_ok=True)
env=dict(os.environ);env.pop('DATABASE_URL',None);env['PYTHONIOENCODING']='utf-8'
commands=[('pytest',[sys.executable,'-m','pytest','-q'],root),('initialize',[sys.executable,'scripts/initialize.py'],root)]
if stage=='baseline':commands.append(('npm_ci',[shutil.which('npm.cmd'),'ci'],root/'etis-frontend'))
commands.extend([(name,[shutil.which('npm.cmd'),'run',task],root/'etis-frontend') for name,task in [('frontend_build','build'),('frontend_lint','lint')]])
r={'stage':stage,'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'branch':subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip(),'python':platform.python_version(),'date':datetime.datetime.now(datetime.timezone.utc).isoformat(),'sealed_test_run':False,'genuine_egyptian_sms_test_count':0,'commands':{}}
for name,cmd,cwd in commands:
 print('Running '+name,flush=True);t=time.perf_counter()
 p=subprocess.run(cmd,cwd=cwd,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace')
 s=p.stdout+p.stderr
 r['commands'][name]={'command':cmd,'exit_code':p.returncode,'seconds':time.perf_counter()-t,'output':s}
 if name=='pytest':
  m=re.search(r'(\d+) passed',s);r['commands'][name]['passed']=int(m[1]) if m else None
 (out/(stage+'_checks.json')).write_text(json.dumps(r,indent=2),encoding='utf-8')
 print(name+': '+str(p.returncode)+'\n'+s[-3000:],flush=True)
