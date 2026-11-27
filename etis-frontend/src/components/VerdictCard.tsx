import type { ReactNode } from 'react';
import { Box, Typography, Stack, Alert } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { AnalyzeResponse } from '../api/types';
import { explainVerdict } from '../api/explainVerdict';
import { VERDICT_STYLE } from '../theme/verdictPalette';

import { VerdictChip } from './VerdictChip';

export function VerdictCard({ result, mascot }: { result: AnalyzeResponse; mascot: ReactNode }) {
 const { t } = useTranslation();
 const style = VERDICT_STYLE[result.verdict];
 return <Box className="etis-result" role="status" aria-live="polite" sx={{ '--scan-color': style.accent, bgcolor: style.bg, border: 1, borderColor: style.border, borderRadius: '16px', p: { xs: 4, sm: 5 } }}>
  <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'center', gap: 2 }}>
    <VerdictChip verdict={result.verdict} />
    {mascot}
  </Stack>
  <Typography variant="h3" component="h2" sx={{mt:2}}>{explainVerdict(t,result)}</Typography>
  {!result.analysis_complete && <Alert severity="warning" sx={{mt:2}}>
   {t('scan.incompleteDetail')}
   <Box component="ul" sx={{mb:0}}>{result.checks_unavailable.map(code=><li key={code}>{t(`reason.${code}`)}</li>)}</Box>
  </Alert>}
  <Box sx={{mt:5}}>
   <Typography variant="h6" component="h3">{t('advice.heading')}</Typography>
   {result.supporting_signals.includes('brand_claim_from_mobile_number')&&<Alert severity="info" sx={{mt:1,mb:2}}>{t('advice.senderType')}</Alert>}
   <Stack component="ul" spacing={1} sx={{paddingInlineStart:5, mb:0}}>
    {(t(`advice.${result.verdict}`,{returnObjects:true}) as string[]).map((item,i)=><Typography component="li" key={i}>{item}</Typography>)}
   </Stack>
  </Box>
 </Box>;
}
