import { useEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { CacheProvider } from '@emotion/react';
import {
  Box, Button, Card, CardContent, Chip, Container, CssBaseline, FormControlLabel,
  Stack, Switch, ThemeProvider, ToggleButton, ToggleButtonGroup, Typography,
} from '@mui/material';
import RadarIcon from '@mui/icons-material/Radar';
import ReportOutlinedIcon from '@mui/icons-material/ReportOutlined';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import LanIcon from '@mui/icons-material/Lan';
import PlayArrowRoundedIcon from '@mui/icons-material/PlayArrowRounded';
import SmsOutlinedIcon from '@mui/icons-material/SmsOutlined';
import LinkOutlinedIcon from '@mui/icons-material/LinkOutlined';
import InsertDriveFileOutlinedIcon from '@mui/icons-material/InsertDriveFileOutlined';
import ShieldOutlinedIcon from '@mui/icons-material/ShieldOutlined';
import GppGoodOutlinedIcon from '@mui/icons-material/GppGoodOutlined';
import GppMaybeOutlinedIcon from '@mui/icons-material/GppMaybeOutlined';
import GppBadOutlinedIcon from '@mui/icons-material/GppBadOutlined';
import LockOutlinedIcon from '@mui/icons-material/LockOutlined';
import HubOutlinedIcon from '@mui/icons-material/HubOutlined';
import SpeedOutlinedIcon from '@mui/icons-material/SpeedOutlined';

import { createConsoleTheme } from '../theme/consoleTheme';
import { createLtrCache, createRtlCache } from '../theme/rtlCache';
import { cssVars, MOTION, TOKENS, TYPE_SCALE, type ColorMode, type VerdictKey } from '../theme/tokens';
import { EtisBot } from '../components/EtisBot';
import { BOT_STATES, botStateFor } from '../components/botState';
import { ScanSurface } from '../components/ScanSurface';
import { ConsoleHeader } from '../components/ConsoleHeader';
import { type PageKey } from '../navigation';

/**
 * /design-preview — console redesign v1 review page (docs/design/console-redesign-v1.md).
 * Shows tokens, cards, the ETIS bot and the scan animation with sample, inert content only.
 * Query params for screenshots: ?theme=light|dark&lang=ar|en&motion=reduced.
 */
const MONO = '"IBM Plex Mono", ui-monospace, monospace';
const VERDICTS: VerdictKey[] = ['LOW', 'MEDIUM', 'HIGH'];
const VERDICT_ICON: Record<VerdictKey, ReactNode> = {
  LOW: <GppGoodOutlinedIcon />, MEDIUM: <GppMaybeOutlinedIcon />, HIGH: <GppBadOutlinedIcon />,
};

function initialMode(): ColorMode {
  const q = new URLSearchParams(location.search).get('theme');
  if (q === 'light' || q === 'dark') return q;
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function Section({ id, title, lead, children }: { id: string; title: string; lead?: string; children: ReactNode }) {
  return (
    <Box component="section" aria-labelledby={id} sx={{ mt: 12 }}>
      <Typography id={id} variant="h3" component="h2">{title}</Typography>
      {lead && <Typography color="text.secondary" sx={{ mt: 1, maxWidth: 720 }}>{lead}</Typography>}
      <Box sx={{ mt: 5 }}>{children}</Box>
    </Box>
  );
}

function Swatch({ name, hex, ring }: { name: string; hex: string; ring?: boolean }) {
  return (
    <Stack direction="row" spacing={3} sx={{ alignItems: 'center', minWidth: 0 }}>
      <Box sx={{ width: 40, height: 40, flex: 'none', borderRadius: 2, bgcolor: hex, border: 1, borderColor: ring ? 'divider' : 'transparent' }} />
      <Box sx={{ minWidth: 0 }}>
        <Typography variant="body2" sx={{ fontWeight: 600 }}>{name}</Typography>
        <Typography variant="caption" color="text.secondary" sx={{ fontFamily: MONO }} dir="ltr">{hex}</Typography>
      </Box>
    </Stack>
  );
}

const grid = (md: number) => ({ display: 'grid', gap: 4, gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, minmax(0, 1fr))', md: `repeat(${md}, minmax(0, 1fr))` } });

export default function DesignPreview() {
  const { t, i18n } = useTranslation();
  const [mode, setMode] = useState<ColorMode>(initialMode);
  const [reduced, setReduced] = useState(() => new URLSearchParams(location.search).get('motion') === 'reduced');
  const [nav, setNav] = useState<PageKey>('scan');
  const [target, setTarget] = useState<VerdictKey>('MEDIUM');
  const [demo, setDemo] = useState<'idle' | 'scanning' | VerdictKey>('idle');
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => {
    const lang = new URLSearchParams(location.search).get('lang');
    if (lang === 'en' || lang === 'ar') i18n.changeLanguage(lang);
  }, [i18n]);
  useEffect(() => () => window.clearTimeout(timer.current), []);

  const isRtl = i18n.language === 'ar';
  const direction = isRtl ? 'rtl' : 'ltr';
  const theme = useMemo(() => createConsoleTheme(mode, direction), [mode, direction]);
  const cache = useMemo(() => (isRtl ? createRtlCache() : createLtrCache()), [isRtl]);
  useEffect(() => {
    document.documentElement.dir = direction;
    document.documentElement.lang = i18n.language;
    document.documentElement.style.colorScheme = mode;
  }, [direction, i18n.language, mode]);

  const tok = TOKENS[mode];
  function runScan() {
    window.clearTimeout(timer.current);
    setDemo('scanning');
    timer.current = window.setTimeout(() => setDemo(target), 2800);
  }

  return (
    <CacheProvider value={cache}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Box style={cssVars(mode) as CSSProperties} data-motion={reduced ? 'reduced' : 'full'} sx={{ minHeight: '100%', pb: 16 }}>
          <ConsoleHeader page={nav} mode={mode} onNavigate={setNav}
            onToggleMode={() => setMode(mode === 'light' ? 'dark' : 'light')} />

          <Container maxWidth="lg" component="main" className="etis-page-in" key={`${mode}-${direction}`} sx={{ pt: 10, px: { xs: 4, sm: 6 } }}>
            {/* Hero */}
            <Stack direction={{ xs: 'column', md: 'row' }} spacing={8} sx={{ alignItems: { md: 'center' } }}>
              <Box sx={{ flex: 1 }}>
                <Chip icon={<ShieldOutlinedIcon />} label={t('designPreview.badge')} color="primary" variant="outlined" />
                <Typography variant="h1" sx={{ mt: 4 }}>{t('designPreview.title')}</Typography>
                <Typography color="text.secondary" sx={{ mt: 3, maxWidth: 620, fontSize: TYPE_SCALE.lead }}>{t('designPreview.intro')}</Typography>
                <FormControlLabel sx={{ mt: 4 }}
                  control={<Switch checked={reduced} onChange={(e) => setReduced(e.target.checked)} />}
                  label={t('designPreview.controls.reducedMotion')} />
              </Box>
              <Stack direction="row" spacing={4} sx={{ alignItems: 'center' }}>
                <EtisBot state="idle" size={120} tip />
              </Stack>
            </Stack>

            {/* Palette */}
            <Section id="dp-palette" title={t('designPreview.palette.title')} lead={t(mode === 'light' ? 'designPreview.palette.leadLight' : 'designPreview.palette.leadDark')}>
              <Card><CardContent sx={{ p: 5 }}>
                <Typography variant="overline" color="text.secondary">{t('designPreview.palette.base')}</Typography>
                <Box sx={{ ...grid(4), mt: 3 }}>
                  <Swatch name={t('designPreview.palette.bg')} hex={tok.bg} ring />
                  <Swatch name={t('designPreview.palette.surface')} hex={tok.surface} ring />
                  <Swatch name={t('designPreview.palette.surface2')} hex={tok.surface2} ring />
                  <Swatch name={t('designPreview.palette.border')} hex={tok.border} ring />
                  <Swatch name={t('designPreview.palette.text')} hex={tok.text} />
                  <Swatch name={t('designPreview.palette.muted')} hex={tok.textMuted} />
                  <Swatch name={t('designPreview.palette.navy')} hex={tok.navy} ring />
                  <Swatch name={t('designPreview.palette.accent')} hex={tok.accent} />
                </Box>
                <Typography variant="overline" color="text.secondary" component="div" sx={{ mt: 6 }}>{t('designPreview.palette.verdicts')}</Typography>
                <Box sx={{ ...grid(3), mt: 3 }}>
                  {VERDICTS.map((v) => (
                    <Stack key={v} spacing={2} sx={{ p: 3, borderRadius: 2, bgcolor: tok.verdict[v].tint, border: 1, borderColor: tok.verdict[v].border }}>
                      <Typography sx={{ color: tok.verdict[v].text, fontWeight: 700 }}>{v} · {t(`verdict.${v}`)}</Typography>
                      <Swatch name={t('designPreview.palette.verdictText')} hex={tok.verdict[v].text} />
                      <Swatch name={t('designPreview.palette.verdictSolid')} hex={tok.verdict[v].solid} />
                      <Swatch name={t('designPreview.palette.verdictTint')} hex={tok.verdict[v].tint} ring />
                    </Stack>
                  ))}
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 4 }}>{t('designPreview.palette.contrast')}</Typography>
              </CardContent></Card>
            </Section>

            {/* Typography */}
            <Section id="dp-type" title={t('designPreview.type.title')} lead={t('designPreview.type.lead')}>
              <Card><CardContent sx={{ p: 5 }}>
                <Stack spacing={3}>
                  {(['h1', 'h2', 'h3', 'h4'] as const).map((v) => (
                    <Stack key={v} direction="row" spacing={4} sx={{ alignItems: 'baseline' }}>
                      <Typography variant="caption" color="text.secondary" sx={{ width: 56, flex: 'none', fontFamily: MONO }} dir="ltr">
                        {TYPE_SCALE[v === 'h4' ? 'lead' : v]}px
                      </Typography>
                      <Typography variant={v} component="div" sx={{ minWidth: 0 }}>{t('designPreview.type.heading')}</Typography>
                    </Stack>
                  ))}
                  <Stack direction="row" spacing={4} sx={{ alignItems: 'baseline' }}>
                    <Typography variant="caption" color="text.secondary" sx={{ width: 56, flex: 'none', fontFamily: MONO }} dir="ltr">15px</Typography>
                    <Typography>{t('designPreview.type.body')}</Typography>
                  </Stack>
                  <Stack direction="row" spacing={4} sx={{ alignItems: 'baseline' }}>
                    <Typography variant="caption" color="text.secondary" sx={{ width: 56, flex: 'none', fontFamily: MONO }} dir="ltr">13px</Typography>
                    <Typography sx={{ fontFamily: MONO, fontSize: TYPE_SCALE.small }} dir="ltr">score 0.987 · 2026-11-27 14:02 · T1566.002</Typography>
                  </Stack>
                </Stack>
              </CardContent></Card>
            </Section>

            {/* Cards */}
            <Section id="dp-cards" title={t('designPreview.cards.title')} lead={t('designPreview.cards.lead')}>
              <Box sx={grid(4)}>
                {([
                  ['openIncidents', '12', <ReportOutlinedIcon key="i" />],
                  ['scansToday', '248', <RadarIcon key="i" />],
                  ['highAlerts', '3', <GppBadOutlinedIcon key="i" />],
                  ['engines', '4 / 4', <SpeedOutlinedIcon key="i" />],
                ] as [string, string, ReactNode][]).map(([key, value, icon]) => (
                  <Card key={key} className="etis-lift">
                    <CardContent sx={{ p: 5 }}>
                      <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'center' }}>
                        <Typography variant="body2" color="text.secondary">{t(`designPreview.cards.${key}`)}</Typography>
                        <Box sx={{ color: 'primary.main', display: 'flex' }}>{icon}</Box>
                      </Stack>
                      <Typography variant="h2" component="div" sx={{ mt: 2, fontFamily: MONO, fontWeight: 600 }} dir="ltr">{value}</Typography>
                    </CardContent>
                  </Card>
                ))}
              </Box>
              <Box sx={{ ...grid(3), mt: 4 }}>
                {VERDICTS.map((v) => (
                  <Box key={v} className="etis-lift" sx={{ p: 5, borderRadius: 3, bgcolor: tok.verdict[v].tint, border: 1, borderColor: tok.verdict[v].border }}>
                    <Stack direction="row" spacing={2} sx={{ alignItems: 'center', color: tok.verdict[v].text }}>
                      {VERDICT_ICON[v]}
                      <Typography sx={{ fontWeight: 700 }}>{t(`verdict.${v}`)}</Typography>
                    </Stack>
                    <Typography variant="body2" sx={{ mt: 2 }}>{t(`designPreview.cards.verdict${v}`)}</Typography>
                  </Box>
                ))}
              </Box>
              <Box sx={{ ...grid(4), mt: 4 }}>
                {([
                  ['phishing', <LockOutlinedIcon key="i" />], ['host', <HubOutlinedIcon key="i" />],
                  ['malware', <FingerprintIcon key="i" />], ['network', <LanIcon key="i" />],
                ] as [string, ReactNode][]).map(([key, icon]) => (
                  <Card key={key} className="etis-lift">
                    <CardContent sx={{ p: 4 }}>
                      <Stack direction="row" spacing={3} sx={{ alignItems: 'center' }}>
                        <Box sx={{ width: 40, height: 40, borderRadius: 2, display: 'grid', placeItems: 'center', bgcolor: tok.accentSoft, color: 'primary.main', flex: 'none' }}>{icon}</Box>
                        <Box sx={{ minWidth: 0 }}>
                          <Typography sx={{ fontWeight: 600 }}>{t(`designPreview.engines.${key}`)}</Typography>
                          <Typography variant="caption" color="text.secondary">{t('designPreview.engines.available')}</Typography>
                        </Box>
                      </Stack>
                    </CardContent>
                  </Card>
                ))}
              </Box>
            </Section>

            {/* Mascot */}
            <Section id="dp-bot" title={t('designPreview.bot.title')} lead={t('designPreview.bot.lead')}>
              <Box sx={{ display: 'grid', gap: 4, gridTemplateColumns: { xs: 'repeat(2, minmax(0, 1fr))', sm: 'repeat(3, minmax(0, 1fr))', md: 'repeat(5, minmax(0, 1fr))' } }}>
                {BOT_STATES.map((s) => (
                  <Card key={s}>
                    <CardContent sx={{ p: 4, display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', gap: 2 }}>
                      <EtisBot state={s} size={88} />
                      <Typography sx={{ fontWeight: 700 }}>{t(`mascot.state.${s}`)}</Typography>
                      <Typography variant="body2" color="text.secondary">{t(`mascot.tips.${s}`)}</Typography>
                    </CardContent>
                  </Card>
                ))}
              </Box>
            </Section>

            {/* Scan animation */}
            <Section id="dp-scan" title={t('designPreview.scan.title')} lead={t('designPreview.scan.lead')}>
              <Card><CardContent sx={{ p: 5 }}>
                <Stack direction={{ xs: 'column', sm: 'row' }} spacing={3} sx={{ alignItems: { sm: 'center' }, flexWrap: 'wrap', rowGap: 3 }}>
                  <Typography variant="body2" color="text.secondary">{t('designPreview.scan.resultLabel')}</Typography>
                  <ToggleButtonGroup exclusive size="small" value={target} onChange={(_, v: VerdictKey | null) => v && setTarget(v)} aria-label={t('designPreview.scan.resultLabel')}>
                    {VERDICTS.map((v) => <ToggleButton key={v} value={v}>{v}</ToggleButton>)}
                  </ToggleButtonGroup>
                  <Button variant="contained" startIcon={<PlayArrowRoundedIcon />} onClick={runScan} disabled={demo === 'scanning'}>
                    {t('designPreview.scan.run')}
                  </Button>
                </Stack>
                <Stack direction={{ xs: 'column', md: 'row' }} spacing={6} sx={{ mt: 5, alignItems: { md: 'center' } }}>
                  <Stack spacing={3} sx={{ flex: 1, minWidth: 0 }}>
                    <ScanSurface status={demo} icon={<SmsOutlinedIcon />} title={t('designPreview.scan.message')}>
                      <Typography variant="body2" sx={{ mt: 1 }} dir="auto">{t('designPreview.scan.messageSample')}</Typography>
                      <Typography variant="caption" color="text.secondary">{t('designPreview.sample')}</Typography>
                    </ScanSurface>
                    <ScanSurface status={demo} icon={<InsertDriveFileOutlinedIcon />} title={t('designPreview.scan.file')}>
                      <Typography variant="body2" sx={{ mt: 1, fontFamily: MONO, overflowWrap: 'anywhere' }} dir="ltr">sample-invoice.pdf · sha256 3f9a…c21e</Typography>
                    </ScanSurface>
                    <ScanSurface status={demo} variant="radar" icon={<LanIcon fontSize="small" />} title={t('designPreview.scan.network')}>
                      <Typography variant="body2" sx={{ mt: 1 }}>{t('designPreview.scan.networkSample')}</Typography>
                    </ScanSurface>
                  </Stack>
                  <Stack sx={{ alignItems: 'center' }}>
                    <EtisBot state={botStateFor(demo)} size={104} tip />
                  </Stack>
                </Stack>
              </CardContent></Card>

              <Typography variant="overline" color="text.secondary" component="div" sx={{ mt: 6 }}>{t('designPreview.scan.frames')}</Typography>
              <Box sx={{ ...grid(2), mt: 3 }}>
                {(['scanning', 'LOW', 'MEDIUM', 'HIGH'] as const).map((s) => (
                  <ScanSurface key={s} status={s} icon={<LinkOutlinedIcon />} title={t('designPreview.scan.url')}>
                    <Typography variant="body2" sx={{ mt: 1, fontFamily: MONO, overflowWrap: 'anywhere' }} dir="ltr">example.com/account/verify</Typography>
                  </ScanSurface>
                ))}
                <ScanSurface status="scanning" variant="radar" icon={<LanIcon fontSize="small" />} title={t('designPreview.scan.network')}>
                  <Typography variant="body2" sx={{ mt: 1 }}>{t('designPreview.scan.networkSample')}</Typography>
                </ScanSurface>
                <ScanSurface status="HIGH" variant="radar" icon={<LanIcon fontSize="small" />} title={t('designPreview.scan.network')}>
                  <Typography variant="body2" sx={{ mt: 1 }}>{t('designPreview.scan.networkSample')}</Typography>
                </ScanSurface>
              </Box>
            </Section>

            {/* Motion */}
            <Section id="dp-motion" title={t('designPreview.motion.title')} lead={t('designPreview.motion.lead')}>
              <Box sx={grid(4)}>
                {([
                  ['fast', MOTION.fast], ['base', MOTION.base], ['slow', MOTION.slow], ['scanCycle', MOTION.scanCycle],
                ] as [string, number][]).map(([key, ms]) => (
                  <Card key={key}><CardContent sx={{ p: 4 }}>
                    <Typography variant="h3" component="div" sx={{ fontFamily: MONO }} dir="ltr">{ms} ms</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>{t(`designPreview.motion.${key}`)}</Typography>
                  </CardContent></Card>
                ))}
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 4 }}>{t('designPreview.motion.reduced')}</Typography>
            </Section>

            <Typography variant="body2" color="text.secondary" sx={{ mt: 12, textAlign: 'center' }}>{t('designPreview.footer')}</Typography>
          </Container>
        </Box>
      </ThemeProvider>
    </CacheProvider>
  );
}
