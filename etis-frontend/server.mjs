// Same-origin server proxy. Secrets stay in this process, never in the browser bundle.
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root=path.dirname(fileURLToPath(import.meta.url));
const envFile=path.join(root,'../.env');
if(fs.existsSync(envFile))for(const line of fs.readFileSync(envFile,'utf8').split(/\r?\n/)){
 const m=line.match(/^([A-Z_]+)=(.*)$/);if(m&&!process.env[m[1]])process.env[m[1]]=m[2].replace(/^['"]|['"]$/g,'');
}
const key=process.env.ETIS_API_KEY;
if(!key)throw new Error('Set ETIS_API_KEY in the server environment before starting the proxy.');
const secret=crypto.randomBytes(32), limits=new Map();
const sign=s=>crypto.createHmac('sha256',secret).update(s).digest('hex');
function validSession(value=''){
 if(!/^[a-f0-9]{32}\.[0-9]{13}\.[a-f0-9]{64}$/.test(value))return false;
 const [id,stamp,sig]=value.split('.');
 if(!id||!stamp||!sig||Date.now()-Number(stamp)>86400000||Number(stamp)>Date.now())return false;
 const expected=sign(id+'.'+stamp);return sig.length===expected.length&&crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected));
}
function allowed(identity){
 const now=Date.now();if(limits.size>4096)for(const [k,v] of limits)if(now-v.at>60000)limits.delete(k);
 const item=limits.get(identity)||{at:now,count:0};if(now-item.at>=60000){item.at=now;item.count=0;}
 item.count++;limits.set(identity,item);return item.count<=60;
}
const mime={'.html':'text/html; charset=utf-8','.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'};
const server=http.createServer(async(req,res)=>{
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');
 res.setHeader('Content-Security-Policy',"default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'");
 try{
  const hostname=new URL('http://'+req.headers.host).hostname;
  const allowedHosts=(process.env.ETIS_ALLOWED_HOSTS||'127.0.0.1,localhost,[::1]').split(',');
  if(!allowedHosts.includes(hostname)){res.writeHead(403);res.end();return;}
  const url=new URL(req.url,'http://localhost');
  if(url.pathname.startsWith('/api/')){
   if(!['/api/analyze','/api/threats','/api/stats','/api/health/ready'].includes(url.pathname)){res.writeHead(404);res.end();return;}
   if(req.headers.origin&&new URL(req.headers.origin).host!==req.headers.host){res.writeHead(403);res.end();return;}
   if(!allowed('ip:'+req.socket.remoteAddress)){res.writeHead(429);res.end('{}');return;}
   let session=req.headers.cookie?.match(/(?:^|; )etis_session=([^;]+)/)?.[1];
   if(!validSession(session)){
    const value=crypto.randomBytes(16).toString('hex')+'.'+Date.now();session=value+'.'+sign(value);
    res.setHeader('Set-Cookie',`etis_session=${session}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400${process.env.ETIS_SECURE_COOKIE==='true'?'; Secure':''}`);
   }
   if(!allowed('session:'+session)){res.writeHead(429);res.end('{}');return;}
   let body=Buffer.alloc(0);
   for await(const chunk of req){body=Buffer.concat([body,chunk]);if(body.length>32768){res.writeHead(413);res.end('{}');return;}}
   const upstream=await fetch((process.env.ETIS_BACKEND_URL||'http://127.0.0.1:8000')+url.pathname.slice(4)+url.search,{
    method:req.method,headers:{'Content-Type':'application/json','X-API-Key':key,'X-ETIS-Session':session.split('.')[0]},
    body:req.method==='POST'?body:undefined,signal:AbortSignal.timeout(30000)});
   res.setHeader('Cache-Control','no-store');res.setHeader('Content-Type','application/json');
   res.writeHead(upstream.status);res.end(await upstream.text());return;
  }
  if(req.method!=='GET'){res.writeHead(405);res.end();return;}
  const dist=path.resolve(root,'dist');let target=path.resolve(dist,'.'+decodeURIComponent(url.pathname));
  if(!target.startsWith(dist+path.sep)&&target!==dist){res.writeHead(403);res.end();return;}
  if(['/','/scan','/threats','/stats'].includes(url.pathname))target=path.join(dist,'index.html');
  if(!fs.existsSync(target)||!fs.statSync(target).isFile()){res.writeHead(404);res.end();return;}
  res.setHeader('Content-Type',mime[path.extname(target)]||'application/octet-stream');
  fs.createReadStream(target).pipe(res);
 }catch{res.writeHead(502,{'Content-Type':'application/json'});res.end('{"detail":"service_unavailable"}');}
});
server.listen(Number(process.env.PORT||5173),process.env.ETIS_WEB_HOST||'127.0.0.1',()=>console.log('ETIS web proxy ready'));
