import type { FormEvent, ReactNode } from 'react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  MenuItem,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';

import { ApiError, getCommunityReports, lookupIndicator, reviewCommunityReport } from '../api/client';
import { shortHash } from '../api/inert';
import type { CommunityReport, HashAlgo, IndicatorDetail, IndicatorType } from '../api/socTypes';
import { InertValue } from '../components/InertValue';
import { IndicatorValue } from '../components/IndicatorValue';
import { SeverityChip, StatusChip, Timestamp } from '../components/SocChips';

const TYPES: IndicatorType[] = ['url', 'domain', 'ip', 'phone', 'email', 'hash'];
const HASH_ALGOS: HashAlgo[] = ['sha256', 'sha1', 'md5'];

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Box sx={{ mt: 10 }}>
      <Typography variant="h4" component="h3" sx={{ mb: 3 }}>{title}</Typography>
      {children}
    </Box>
  );
}

export function IndicatorsPage() {
  const { t } = useTranslation();
  const [type, setType] = useState<IndicatorType>('url');
  const [hashAlgo, setHashAlgo] = useState<HashAlgo>('sha256');
  const [value, setValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ found: boolean; indicator: IndicatorDetail | null } | null>(null);

  async function search(event: FormEvent) {
    event.preventDefault();
    if (!value.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      setResult(await lookupIndicator(type, value.trim(), hashAlgo));
    } catch (err) {
      setError(err instanceof ApiError && err.status === 400 ? 'indicators.invalidValue' : 'error.requestFailed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <Box>
      <Typography variant="h1" component="h1" gutterBottom>{t('nav.indicators')}</Typography>
      <Typography color="text.secondary" sx={{ mb: 5 }}>{t('indicators.intro')}</Typography>

      <Paper variant="outlined" component="form" onSubmit={search} sx={{ p: { xs: 4, sm: 5 } }}>
        <Stack direction="row" useFlexGap sx={{ gap: 4, flexWrap: 'wrap', alignItems: 'center' }}>
          <TextField select size="small" label={t('soc.indicatorType')} value={type} sx={{ minWidth: { xs: '100%', sm: 150 } }}
            onChange={(e) => { setType(e.target.value as IndicatorType); setResult(null); }}>
            {TYPES.map((item) => <MenuItem key={item} value={item}>{t(`soc.type.${item}`)}</MenuItem>)}
          </TextField>
          {type === 'hash' && (
            <TextField select size="small" label={t('indicators.hashAlgo')} value={hashAlgo} sx={{ minWidth: 120 }}
              onChange={(e) => setHashAlgo(e.target.value as HashAlgo)}>
              {HASH_ALGOS.map((item) => <MenuItem key={item} value={item}>{item}</MenuItem>)}
            </TextField>
          )}
          <TextField size="small" label={t('indicators.value')} value={value} sx={{ flex: 1, minWidth: { xs: '100%', sm: 220 } }}
            autoComplete="off" slotProps={{ htmlInput: { dir: 'ltr', spellCheck: false, maxLength: 2048 } }}
            onChange={(e) => setValue(e.target.value)} />
          <Button type="submit" variant="contained" disabled={loading || !value.trim()}>{t('indicators.search')}</Button>
        </Stack>
        <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 1 }}>{t('indicators.privacy')}</Typography>
      </Paper>

      {loading && <CircularProgress size={24} sx={{ mt: 2 }} aria-label={t('scan.loading')} />}
      {error && <Alert severity="error" sx={{ mt: 2 }}>{t(error)}</Alert>}
      {result && !result.found && (
        <Paper variant="outlined" sx={{ mt: 2, p: 6, textAlign: 'center' }}>
          <Typography variant="body2" color="text.secondary">{t('indicators.notFound')}</Typography>
        </Paper>
      )}
      {result?.indicator && <IndicatorDetailCard indicator={result.indicator} />}

      <CommunityReview />
    </Box>
  );
}

function IndicatorDetailCard({ indicator }: { indicator: IndicatorDetail }) {
  const { t } = useTranslation();
  return (
    <Paper variant="outlined" sx={{ mt: 8, p: { xs: 4, sm: 5 }, overflowWrap: 'anywhere' }} aria-live="polite">
      <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
        <Chip size="small" label={t(`soc.type.${indicator.type}`)} />
        {indicator.value ? <IndicatorValue type={indicator.type} value={indicator.value} copyable /> : (
          <Typography variant="body2" color="text.secondary">{t('indicators.hashOnly')}</Typography>
        )}
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
        sha256 <InertValue value={shortHash(indicator.value_hash)} muted />
        {indicator.registered_domain && <> · {t('indicators.registeredDomain')}: <IndicatorValue type="domain" value={indicator.registered_domain} /></>}
      </Typography>
      <Typography variant="body2" color="text.secondary">
        {t('indicators.firstSeen')}: <Timestamp value={indicator.first_seen} /> · {t('indicators.lastSeen')}: <Timestamp value={indicator.last_seen} />
      </Typography>

      <Section title={t('indicators.sightings', { count: indicator.sightings.length })}>
        <Paper variant="outlined" sx={{ overflowX: 'auto' }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 600 }}>{t('indicators.sourceKind')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('indicators.sourceName')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('indicators.firstSeen')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('indicators.lastSeen')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('threats.active')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {indicator.sightings.map((s) => (
                <TableRow key={`${s.source_kind}:${s.source_name}`}>
                  <TableCell>{t(`soc.sourceKind.${s.source_kind}`, { defaultValue: s.source_kind })}</TableCell>
                  <TableCell>{t(`source.${s.source_name}`, { defaultValue: s.source_name })}</TableCell>
                  <TableCell><Timestamp value={s.first_seen} /></TableCell>
                  <TableCell><Timestamp value={s.last_seen} /></TableCell>
                  <TableCell>
                    <Chip size="small" color={s.active ? 'primary' : 'default'} label={s.active ? t('threats.active') : t('threats.inactive')} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      </Section>

      <Section title={t('indicators.findings', { count: indicator.findings.length })}>
        {indicator.findings.length === 0 ? (
          <Typography variant="body2" color="text.secondary">—</Typography>
        ) : (
          <Paper variant="outlined" sx={{ overflowX: 'auto' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 600 }}>{t('incidents.observed')}</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{t('incidents.kind')}</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{t('incidents.severity')}</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{t('incidents.roles')}</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{t('incidents.title')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {indicator.findings.map((f) => (
                  <TableRow key={`${f.id}:${f.role}`}>
                    <TableCell><Timestamp value={f.observed_at} /></TableCell>
                    <TableCell>{t(`soc.kind.${f.kind}`, { defaultValue: f.kind })}</TableCell>
                    <TableCell><SeverityChip severity={f.severity} /></TableCell>
                    <TableCell>{t(`soc.role.${f.role}`, { defaultValue: f.role })}</TableCell>
                    <TableCell dir="ltr">{f.incident_id ? `#${f.incident_id}` : '—'}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Paper>
        )}
      </Section>

      <Section title={t('indicators.incidents', { count: indicator.incidents.length })}>
        {indicator.incidents.length === 0 ? (
          <Typography variant="body2" color="text.secondary">—</Typography>
        ) : (
          <Stack spacing={1}>
            {indicator.incidents.map((i) => (
              <Stack key={i.id} direction="row" useFlexGap sx={{ gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
                <Typography variant="body2" dir="ltr" sx={{ fontFamily: "'IBM Plex Mono', monospace" }}>#{i.id}</Typography>
                <SeverityChip severity={i.severity} />
                <StatusChip status={i.status} />
              </Stack>
            ))}
            <Typography variant="caption" color="text.secondary">{t('indicators.openInIncidents')}</Typography>
          </Stack>
        )}
      </Section>
    </Paper>
  );
}

function CommunityReview() {
  const { t } = useTranslation();
  const [reports, setReports] = useState<CommunityReport[]>([]);
  const [total, setTotal] = useState(0);
  const [types, setTypes] = useState<Record<number, IndicatorType>>({});
  const [error, setError] = useState<string | null>(null);
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    let cancelled = false;
    Promise.all([getCommunityReports(), getCommunityReports('pending')])
      .then(([all, pending]) => {
        if (!cancelled) {
          setTotal(all.total_matching);
          setReports(pending.results);
        }
      })
      .catch(() => {
        if (!cancelled) setTotal(0);
      });
    return () => {
      cancelled = true;
    };
  }, [refresh]);

  async function review(id: number, status: 'confirmed' | 'rejected') {
    setError(null);
    try {
      await reviewCommunityReport(id, status, types[id]);
      setRefresh((r) => r + 1);
    } catch (err) {
      setError(err instanceof ApiError && err.status === 400 ? 'indicators.reportValueInvalid' : 'error.requestFailed');
    }
  }

  // Shown only when community reports exist (design §6); public reporting stays deferred.
  if (total === 0) return null;
  return (
    <Section title={t('indicators.communityHeading')}>
      <Typography variant="caption" color="text.secondary" component="p" sx={{ mb: 1 }}>{t('indicators.communityHelp')}</Typography>
      {error && <Alert severity="error" sx={{ mb: 1 }}>{t(error)}</Alert>}
      {reports.length === 0 ? (
        <Typography variant="body2" color="text.secondary">{t('indicators.noPending')}</Typography>
      ) : (
        <Paper variant="outlined" sx={{ overflowX: 'auto' }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 600 }}>{t('indicators.reported')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('indicators.reporterNote')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('indicators.submitted')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('incidents.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {reports.map((r) => (
                <TableRow key={r.id}>
                  <TableCell><IndicatorValue value={r.reported_value} copyable /></TableCell>
                  <TableCell sx={{ overflowWrap: 'anywhere' }}>{r.reporter_note ?? '—'}</TableCell>
                  <TableCell><Timestamp value={r.submitted_at} /></TableCell>
                  <TableCell>
                    <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
                      <TextField select size="small" label={t('soc.indicatorType')} value={types[r.id] ?? ''} sx={{ minWidth: 130 }}
                        onChange={(e) => setTypes((current) => ({ ...current, [r.id]: e.target.value as IndicatorType }))}>
                        {TYPES.filter((item) => item !== 'hash').map((item) => <MenuItem key={item} value={item}>{t(`soc.type.${item}`)}</MenuItem>)}
                      </TextField>
                      <Button size="small" variant="outlined" disabled={!types[r.id]} onClick={() => review(r.id, 'confirmed')}>
                        {t('indicators.confirm')}
                      </Button>
                      <Button size="small" onClick={() => review(r.id, 'rejected')}>{t('indicators.reject')}</Button>
                    </Stack>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      )}
    </Section>
  );
}
