import { useEffect, useState } from 'react'
import { Alert, Box, Button, Card, CardContent, Chip, CircularProgress, Container, LinearProgress, Paper, Stack, Tab, Tabs, TextField, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { api, AnalyzeResponse, Stats, Threat } from './api'

type Page = 'scan' | 'threats' | 'stats'

function ScanPage() {
  const { t } = useTranslation()
  const [url, setUrl] = useState('')
  const [text, setText] = useState('')
  const [result, setResult] = useState<AnalyzeResponse | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const submit = async () => {
    if (!url.trim() && !text.trim()) return setError(t('emptyInput'))
    setLoading(true); setError('')
    try { setResult(await api.analyze({ url: url.trim() || undefined, text: text.trim() || undefined })) }
    catch (e) { setError(e instanceof Error ? e.message : t('loadError')) }
    finally { setLoading(false) }
  }
  const color = result?.verdict === 'HIGH' ? 'error' : result?.verdict === 'MEDIUM' ? 'warning' : 'success'
  return <Stack spacing={3}>
    <Paper className="scan-panel"><Stack spacing={2}>
      <TextField label={t('url')} value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com" fullWidth dir="ltr"/>
      <TextField label={t('text')} value={text} onChange={e => setText(e.target.value)} multiline minRows={4} fullWidth/>
      {error && <Alert severity="error">{error}</Alert>}
      <Button variant="contained" size="large" onClick={submit} disabled={loading}>{loading ? t('analyzing') : t('analyze')}</Button>
    </Stack></Paper>
    {loading && <LinearProgress/>}
    {result && <Stack spacing={2}>
      <Card className={`verdict verdict-${result.verdict.toLowerCase()}`}><CardContent>
        <Stack direction="row" justifyContent="space-between" alignItems="center"><Box><Typography variant="overline">{t('result')}</Typography><Typography variant="h3">{result.verdict}</Typography></Box><Chip color={color} label={`${t('score')}: ${result.final_score.toFixed(1)}/100`}/></Stack>
        <Typography sx={{ mt: 2 }}>{result.reason}</Typography>
      </CardContent></Card>
      <Typography variant="h5">{t('engines')}</Typography>
      <Box className="engine-grid">{Object.entries(result.engine_details).map(([name, engine]) => <Card key={name}><CardContent><Typography variant="h6">{name.replace('_', ' ')}</Typography><Typography variant="h4" color={engine.applicable ? 'primary' : 'text.secondary'}>{engine.applicable ? `${engine.score ?? 0}` : '—'}</Typography><Typography color="text.secondary">{engine.reason || t('notApplied')}</Typography></CardContent></Card>)}</Box>
    </Stack>}
  </Stack>
}

function ThreatsPage() {
  const { t } = useTranslation(); const [items, setItems] = useState<Threat[]>([]); const [page, setPage] = useState(1); const [total, setTotal] = useState(0); const [error, setError] = useState('')
  const [source, setSource] = useState(''); const [domain, setDomain] = useState(''); const [filters, setFilters] = useState<{ source?: string; domain?: string }>({})
  useEffect(() => { setError(''); api.threats(page, filters).then(r => { setItems(r.items); setTotal(r.total) }).catch(() => setError(t('loadError'))) }, [page, filters, t])
  const applyFilters = () => { setPage(1); setFilters({ source: source.trim() || undefined, domain: domain.trim() || undefined }) }
  const clearFilters = () => { setSource(''); setDomain(''); setPage(1); setFilters({}) }
  return <Stack spacing={2}>{error && <Alert severity="error">{error}</Alert>}<Paper className="filter-panel"><Stack direction={{ xs: 'column', md: 'row' }} spacing={2}><TextField label={t('sourceFilter')} value={source} onChange={e => setSource(e.target.value)} fullWidth/><TextField label={t('domainFilter')} value={domain} onChange={e => setDomain(e.target.value)} fullWidth dir="ltr"/><Button variant="contained" onClick={applyFilters}>{t('filter')}</Button><Button onClick={clearFilters}>{t('clear')}</Button></Stack></Paper><Paper className="table-wrap"><table><thead><tr><th>{t('domain')}</th><th>{t('source')}</th><th>{t('brand')}</th><th>{t('lastSeen')}</th></tr></thead><tbody>{items.map(item => <tr key={item.id}><td dir="ltr">{item.domain}</td><td>{item.source}</td><td>{item.brand_target || '—'}</td><td>{item.last_seen}</td></tr>)}</tbody></table>{!items.length && <Typography sx={{ p: 3 }}>{t('noThreats')}</Typography>}</Paper><Stack direction="row" justifyContent="space-between"><Button disabled={page === 1} onClick={() => setPage(p => p - 1)}>{t('previous')}</Button><Typography>{t('page')} {page} · {total.toLocaleString()}</Typography><Button disabled={page * 20 >= total} onClick={() => setPage(p => p + 1)}>{t('next')}</Button></Stack></Stack>
}

function StatsPage() {
  const { t } = useTranslation(); const [stats, setStats] = useState<Stats | null>(null); const [error, setError] = useState('')
  useEffect(() => { api.stats().then(setStats).catch(() => setError(t('loadError'))) }, [t])
  if (error) return <Alert severity="error">{error}</Alert>; if (!stats) return <CircularProgress/>
  const Breakdown = ({ title, values }: { title: string; values: Record<string, number> }) => <Card><CardContent><Typography variant="h6" gutterBottom>{title}</Typography>{Object.keys(values).length ? Object.entries(values).map(([name, count]) => <Stack key={name} direction="row" justifyContent="space-between" className="breakdown-row"><Typography>{name}</Typography><Chip size="small" label={count.toLocaleString()}/></Stack>) : <Typography color="text.secondary">{t('noData')}</Typography>}</CardContent></Card>
  return <Stack spacing={2}><Box className="stats-grid"><Card><CardContent><Typography color="text.secondary">{t('blacklistTotal')}</Typography><Typography variant="h3">{stats.blacklist_total.toLocaleString()}</Typography></CardContent></Card><Card><CardContent><Typography color="text.secondary">{t('scansTotal')}</Typography><Typography variant="h3">{stats.scans_total.toLocaleString()}</Typography></CardContent></Card><Card><CardContent><Typography color="text.secondary">{t('model')}</Typography><Typography variant="h3">{stats.model_available ? t('available') : t('unavailable')}</Typography></CardContent></Card></Box><Box className="breakdown-grid"><Breakdown title={t('sourceBreakdown')} values={stats.blacklist_by_source}/><Breakdown title={t('verdictBreakdown')} values={stats.verdict_counts}/></Box></Stack>
}

export default function App({ direction, onDirectionChange }: { direction: 'rtl' | 'ltr'; onDirectionChange: (value: 'rtl' | 'ltr') => void }) {
  const { t, i18n } = useTranslation(); const [page, setPage] = useState<Page>('scan')
  const toggle = async () => { const language = i18n.language === 'ar' ? 'en' : 'ar'; await i18n.changeLanguage(language); const dir = language === 'ar' ? 'rtl' : 'ltr'; document.documentElement.dir = dir; document.documentElement.lang = language; onDirectionChange(dir) }
  return <><Box component="header" className="hero"><Container maxWidth="lg"><Stack direction="row" justifyContent="space-between" alignItems="flex-start"><Box><Typography variant="overline" color="primary">ETIS · v0.1</Typography><Typography variant="h2" className="hero-title">{t('title')}</Typography><Typography color="text.secondary" className="hero-subtitle">{t('subtitle')}</Typography></Box><Button variant="outlined" onClick={toggle}>{t('language')}</Button></Stack></Container></Box><Container maxWidth="lg" className="content"><Tabs value={page} onChange={(_, value) => setPage(value)} variant="fullWidth"><Tab value="scan" label={t('scan')}/><Tab value="threats" label={t('threats')}/><Tab value="stats" label={t('stats')}/></Tabs><Box sx={{ mt: 4 }}>{page === 'scan' ? <ScanPage/> : page === 'threats' ? <ThreatsPage/> : <StatsPage/>}</Box></Container></>
}
