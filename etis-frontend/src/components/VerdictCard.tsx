import { Box, Typography, Chip, Stack, Alert } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { AnalyzeResponse } from '../api/types';
import { explainVerdict } from '../api/explainVerdict';
import { VERDICT_STYLE } from '../theme/verdictPalette';

export function VerdictCard({ result }: { result: AnalyzeResponse }) {
 const { t } = useTranslation();
 const style = VERDICT_STYLE[result.verdict];
 return <Box role="status" aria-live="polite" sx={{ bgcolor:style.bg,border:1,borderColor:style.accent,borderRadius:3,p:3 }}>
  <Chip label={t(`verdict.${result.verdict}`)} color={style.chipColor} sx={{fontWeight:700}} />
  <Typography variant="h6" component="h2" sx={{mt:2}}>{explainVerdict(t,result)}</Typography>
  {!result.analysis_complete && <Alert severity="warning" sx={{mt:2}}>
   {t('scan.incompleteDetail')}
   <Box component="ul" sx={{mb:0}}>{result.checks_unavailable.map(code=><li key={code}>{t(`reason.${code}`)}</li>)}</Box>
  </Alert>}
  <Box sx={{mt:3}}>
   <Typography variant="h6" component="h3">{t('advice.heading')}</Typography>
   {result.supporting_signals.includes('brand_claim_from_mobile_number')&&<Alert severity="info" sx={{mt:1,mb:2}}>{t('advice.senderType')}</Alert>}
   <Stack component="ul" spacing={1} sx={{pl:3}}>
    {(t(`advice.${result.verdict}`,{returnObjects:true}) as string[]).map((item,i)=><Typography component="li" key={i}>{item}</Typography>)}
   </Stack>
  </Box>
 </Box>;
}
