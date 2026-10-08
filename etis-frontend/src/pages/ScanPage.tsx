import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Box,TextField,Button,Typography,CircularProgress,Alert,Stack,Paper,Chip } from '@mui/material';
import { analyzeScan,ApiError } from '../api/client';
import type { AnalyzeResponse } from '../api/types';
import { VerdictCard } from '../components/VerdictCard';

export function ScanPage() {
 const {t}=useTranslation();
 const [url,setUrl]=useState(''),[text,setText]=useState('');
 const [loading,setLoading]=useState(false),[error,setError]=useState<string|null>(null);
 const [result,setResult]=useState<AnalyzeResponse|null>(null);
 const mounted=useRef(true);
 useEffect(()=>{mounted.current=true;return ()=>{mounted.current=false}},[]);
 async function handleSubmit(e?:React.FormEvent){
  e?.preventDefault();
  if(!url.trim()&&!text.trim()){setError('inputRequired');return;}
  setLoading(true);setError(null);setResult(null);
  try {
   const response=await analyzeScan({url:url.trim()||undefined,text:text.trim()||undefined});
   if(mounted.current)setResult(response);
  } catch(err){
   if(mounted.current)setError(err instanceof ApiError&&err.status===400?'invalidInput':err instanceof ApiError&&err.status===429?'tooMany':'requestFailed');
   console.error('Scan request failed',err instanceof ApiError?err.status:'network');
  } finally {if(mounted.current)setLoading(false);}
 }
 return <Box sx={{py:4,maxWidth:900,mx:'auto'}}>
  <Typography variant="h4" component="h1" gutterBottom>{t('nav.scan')}</Typography>
  <Typography color="text.secondary">{t('scan.intro')}</Typography>
  <Alert severity="info" sx={{mt:2}}>{t('scan.experimental')}</Alert>
  <Box component="form" onSubmit={handleSubmit} sx={{mt:3,maxWidth:650}}>
   <Stack spacing={2}>
    <TextField label={t('scan.urlLabel')} value={url} disabled={loading} onChange={e=>{setUrl(e.target.value);setResult(null)}} fullWidth slotProps={{htmlInput:{maxLength:2048,dir:'ltr'}}} placeholder="https://example.com" />
    <TextField label={t('scan.textLabel')} value={text} disabled={loading} onChange={e=>{setText(e.target.value);setResult(null)}} fullWidth multiline minRows={4} slotProps={{htmlInput:{maxLength:5000}}} helperText={t('scan.textLimit',{count:text.length})} />
    <Button type="submit" variant="contained" disabled={loading}>{loading?<CircularProgress size={22} aria-label={t('scan.loading')}/>:t('scan.submit')}</Button>
   </Stack>
  </Box>
  {error&&<Alert severity="error" sx={{mt:3}} action={<Button color="inherit" onClick={()=>void handleSubmit()}>{t('common.retry')}</Button>}>{t(`error.${error}`)}</Alert>}
  {result&&<Stack spacing={2} sx={{mt:4}}>
   <VerdictCard result={result}/>
   {!result.saved&&<Alert severity="warning">{t('scan.notSaved')}</Alert>}
   {result.checked_links.length>0&&<Typography variant="h6" component="h2">{t('scan.checkedLinks',{count:result.checked_links.length})}</Typography>}
   {result.checked_links.map((link,index)=><Paper variant="outlined" key={link.url+':'+index} sx={{p:2,overflowWrap:'anywhere'}}>
    <Typography component="span" dir="ltr" sx={{fontFamily:'monospace'}}>{link.host}</Typography>
    {!link.analysis_complete&&<Chip size="small" label={t('verdict.INCOMPLETE')} sx={{m:1}}/>}
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
