import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Box,TextField,Button,Typography,Alert,Stack,Paper,Chip,MenuItem } from '@mui/material';
import { analyzeScan,ApiError } from '../api/client';
import type { AnalyzeResponse,SenderType } from '../api/types';
import SmsOutlinedIcon from '@mui/icons-material/SmsOutlined';
import LinkOutlinedIcon from '@mui/icons-material/LinkOutlined';
import PsychologyOutlinedIcon from '@mui/icons-material/PsychologyOutlined';
import { ScanSurface } from '../components/ScanSurface';
import { EtisBot } from '../components/EtisBot';
import { botStateFor } from '../components/botState';
import { VerdictChip } from '../components/VerdictChip';
import { EngineBreakdownCard } from '../components/EngineBreakdownCard';
import { InertValue } from '../components/InertValue';
import { VerdictCard } from '../components/VerdictCard';

export function ScanPage() {
 const {t}=useTranslation();
 const [url,setUrl]=useState(''),[text,setText]=useState('');
 const [senderType,setSenderType]=useState<SenderType>('unknown');
 const [loading,setLoading]=useState(false),[error,setError]=useState<string|null>(null);
 const [result,setResult]=useState<AnalyzeResponse|null>(null);
 const mounted=useRef(true);
 useEffect(()=>{mounted.current=true;return ()=>{mounted.current=false}},[]);
 async function handleSubmit(e?:React.FormEvent){
  e?.preventDefault();
  if(!url.trim()&&!text.trim()){setError('inputRequired');return;}
  setLoading(true);setError(null);setResult(null);
  try {
   const response=await analyzeScan({url:url.trim()||undefined,text:text.trim()||undefined,sender_type:text.trim()?senderType:undefined});
   if(mounted.current)setResult(response);
  } catch(err){
   if(mounted.current)setError(err instanceof ApiError&&err.status===400?'invalidInput':err instanceof ApiError&&err.status===429?'tooMany':'requestFailed');
   console.error('Scan request failed',err instanceof ApiError?err.status:'network');
  } finally {if(mounted.current)setLoading(false);}
 }
 const status = loading ? 'scanning' : result?.verdict ?? 'idle';
 const bot = <EtisBot state={botStateFor(status === 'INCOMPLETE' ? 'idle' : status)} size={result ? 56 : 92} tip={!result} />;
 return <Box>
  <Typography variant="h1" component="h1" gutterBottom>{t('nav.scan')}</Typography>
  <Typography color="text.secondary">{t('scan.intro')}</Typography>
  <Alert severity="info" sx={{mt:4}}>{t('scan.experimental')}</Alert>
  <Box sx={{ mt: 6, display: 'grid', gap: 5, alignItems: 'start',
    gridTemplateColumns: { xs: 'minmax(0, 1fr)', md: 'minmax(0, 3fr) minmax(0, 2fr)' } }}>
   <ScanSurface status={status} title={t('scan.inputHeading')} icon={url && !text ? <LinkOutlinedIcon /> : <SmsOutlinedIcon />}>
    <Stack component="form" onSubmit={handleSubmit} spacing={4}>
     <TextField label={t('scan.urlLabel')} value={url} disabled={loading} onChange={e=>{setUrl(e.target.value);setResult(null)}} fullWidth slotProps={{htmlInput:{maxLength:2048,dir:'ltr'}}} placeholder="https://example.com" />
     <TextField label={t('scan.textLabel')} value={text} disabled={loading} onChange={e=>{setText(e.target.value);setResult(null)}} fullWidth multiline minRows={4} slotProps={{htmlInput:{maxLength:5000,dir:'auto'}}} helperText={t('scan.textLimit',{count:text.length})} />
     <TextField select label={t('scan.senderLabel')} value={senderType} disabled={loading||!text.trim()} onChange={e=>{setSenderType(e.target.value as SenderType);setResult(null)}} fullWidth helperText={t('scan.senderHelp')}>
      {(['unknown','company_name','short_code','mobile_number'] as SenderType[]).map(type=><MenuItem key={type} value={type}>{t(`scan.senderTypes.${type}`)}</MenuItem>)}
     </TextField>
     <Button type="submit" variant="contained" disabled={loading}>{loading ? t('scan.loading') : t('scan.submit')}</Button>
    </Stack>
   </ScanSurface>
   <Stack sx={{ alignItems: 'center', gap: 4, minWidth: 0 }}>
    {result ? <VerdictCard result={result} mascot={bot} /> : bot}
   </Stack>
  </Box>
  {error&&<Alert severity="error" sx={{mt:3}} action={<Button color="inherit" onClick={()=>void handleSubmit()}>{t('common.retry')}</Button>}>{t(`error.${error}`)}</Alert>}
  {result&&<Stack spacing={4} sx={{mt:8}}>
   {result.text_finding && <EngineBreakdownCard title={t('scan.engineLstm')} icon={<PsychologyOutlinedIcon />}
     applicable verdict={result.verdict} score={result.text_finding.score} />}
   {!result.saved&&<Alert severity="warning">{t('scan.notSaved')}</Alert>}
   {result.checked_links.length>0&&<Typography variant="h6" component="h2">{t('scan.checkedLinks',{count:result.checked_links.length})}</Typography>}
   {result.checked_links.map((link,index)=><Paper variant="outlined" key={link.url+':'+index} sx={{p:4,overflowWrap:'anywhere'}}>
    <InertValue value={link.host} />
    {!link.analysis_complete&&<VerdictChip verdict="INCOMPLETE" />}
    {link.brand.decisive&&<Typography sx={{mt:1}}>{t('scan.impersonates')}: {link.brand.matched_brand}</Typography>}
    {link.brand.official_contact&&result.verdict!=='LOW'&&<Typography sx={{mt:1}}>
     {t('scan.officialNumber')}: <Box component="span" dir="ltr">{link.brand.official_contact.phone}</Box>
     {' · '}<a href={link.brand.official_contact.source} target="_blank" rel="noopener noreferrer">{t('scan.officialSource')}</a>
    </Typography>}
    <Stack direction="row" useFlexGap sx={{flexWrap:'wrap',gap:1,mt:1}}>
     {link.blacklist.match_type&&<Chip label={t(`reason.blacklist_${link.blacklist.match_type}`)} />}
     {link.patterns.map(([flag])=><Chip size="small" key={flag} label={t(`pattern.${flag}`)}/>)}
    </Stack>
   </Paper>)}
   <Typography variant="caption" color="text.secondary">{t('scan.totalTime',{ms:result.timing_ms})}</Typography>
  </Stack>}
 </Box>;
}
