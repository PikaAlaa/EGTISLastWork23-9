import type { ReactNode } from 'react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Divider,
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

import {
  ApiError,
  assignCampaign,
  createCampaign,
  getCampaigns,
  getCampaignSuggestions,
  getIncident,
  getIncidents,
  mergeIncident,
  updateIncident,
} from '../api/client';
import type {
  Campaign,
  CampaignSuggestion,
  FindingDomain,
  IncidentDetail,
  IncidentStatus,
  IncidentSummary,
  Resolution,
  Severity,
} from '../api/socTypes';
import { shortHash } from '../api/inert';
import { InertValue } from '../components/InertValue';
import { SeverityChip, StatusChip, Timestamp } from '../components/SocChips';

const PAGE_SIZE = 20;
const MONO_FONT = "'IBM Plex Mono', monospace";
const STATUSES: IncidentStatus[] = ['open', 'investigating', 'resolved'];
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const DOMAINS: FindingDomain[] = ['phishing', 'malware', 'network', 'host'];
const RESOLUTIONS: Resolution[] = ['true_positive', 'false_positive', 'benign', 'duplicate'];
const KNOWN_ERRORS = new Set([
  'resolution_required', 'reopen_note_required', 'invalid_transition', 'cannot_merge_into_itself',
  'merge_requires_active_incidents', 'not_found', 'note_required',
]);

function errorCode(err: unknown): string {
  if (err instanceof ApiError && err.body && typeof err.body === 'object' && 'detail' in err.body) {
    const detail = String((err.body as { detail: unknown }).detail);
    if (KNOWN_ERRORS.has(detail)) return `incidents.errors.${detail}`;
  }
  return 'error.requestFailed';
}

interface Filters {
  status: IncidentStatus | '';
  severity: Severity | '';
  domain: FindingDomain | '';
  brand: string;
  since: string;
  until: string;
}

const EMPTY_FILTERS: Filters = { status: '', severity: '', domain: '', brand: '', since: '', until: '' };

export function IncidentsPage() {
  const { t } = useTranslation();
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
  const [offset, setOffset] = useState(0);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);
  // `/incidents?id=N` opens that incident (links from the File scans page).
  const [selected, setSelected] = useState<number | null>(() => {
    const id = Number(new URLSearchParams(location.search).get('id'));
    return Number.isInteger(id) && id > 0 ? id : null;
  });
  const [suggestions, setSuggestions] = useState<CampaignSuggestion[]>([]);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const response = await getIncidents({
          status: filters.status || undefined,
          severity: filters.severity || undefined,
          domain: filters.domain || undefined,
          brand: filters.brand.trim() || undefined,
          since: filters.since || undefined,
          until: filters.until || undefined,
          limit: PAGE_SIZE,
          offset,
        });
        if (!cancelled) {
          setIncidents(response.results);
          setTotal(response.total_matching);
        }
        const hints = await getCampaignSuggestions();
        if (!cancelled) setSuggestions(hints.results);
      } catch {
        if (!cancelled) setError('error.requestFailed');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [filters, offset, retry]);

  function setFilter<K extends keyof Filters>(key: K, value: Filters[K]) {
    setOffset(0);
    setFilters((current) => ({ ...current, [key]: value }));
  }

  const rangeStart = total === 0 ? 0 : offset + 1;
  const rangeEnd = Math.min(offset + PAGE_SIZE, total);

  return (
    <Box>
      <Typography variant="h1" component="h1" gutterBottom>
        {t('nav.incidents')}
      </Typography>
      <Typography color="text.secondary" sx={{ mb: 5 }}>
        {t('incidents.intro')}
      </Typography>

      <Paper variant="outlined" className="etis-filters">
        <TextField select size="small" label={t('incidents.status')} value={filters.status} sx={{ minWidth: 150 }}
          slotProps={{ select: { displayEmpty: true }, inputLabel: { shrink: true } }}
          onChange={(e) => setFilter('status', e.target.value as Filters['status'])}>
          <MenuItem value="">{t('incidents.any')}</MenuItem>
          {STATUSES.map((s) => <MenuItem key={s} value={s}>{t(`soc.status.${s}`)}</MenuItem>)}
        </TextField>
        <TextField select size="small" label={t('incidents.severity')} value={filters.severity} sx={{ minWidth: 140 }}
          slotProps={{ select: { displayEmpty: true }, inputLabel: { shrink: true } }}
          onChange={(e) => setFilter('severity', e.target.value as Filters['severity'])}>
          <MenuItem value="">{t('incidents.any')}</MenuItem>
          {SEVERITIES.map((s) => <MenuItem key={s} value={s}>{t(`soc.severity.${s}`)}</MenuItem>)}
        </TextField>
        <TextField select size="small" label={t('incidents.domain')} value={filters.domain} sx={{ minWidth: 140 }}
          slotProps={{ select: { displayEmpty: true }, inputLabel: { shrink: true } }}
          onChange={(e) => setFilter('domain', e.target.value as Filters['domain'])}>
          <MenuItem value="">{t('incidents.any')}</MenuItem>
          {DOMAINS.map((d) => <MenuItem key={d} value={d}>{t(`soc.domain.${d}`)}</MenuItem>)}
        </TextField>
        <TextField size="small" label={t('incidents.brand')} value={filters.brand} sx={{ minWidth: 160 }}
          onChange={(e) => setFilter('brand', e.target.value)} />
        <TextField size="small" type="date" label={t('incidents.since')} value={filters.since}
          slotProps={{ inputLabel: { shrink: true } }} onChange={(e) => setFilter('since', e.target.value)} />
        <TextField size="small" type="date" label={t('incidents.until')} value={filters.until}
          slotProps={{ inputLabel: { shrink: true } }} onChange={(e) => setFilter('until', e.target.value)} />
        <Typography variant="body2" color="text.secondary">
          <Box component="span" sx={{ fontFamily: MONO_FONT }}>{total.toLocaleString()}</Box>{' '}
          {t('threats.totalMatching')}
        </Typography>
      </Paper>

      {suggestions.length > 0 && (
        <Alert severity="info" sx={{ mb: 2 }}>
          <Typography variant="subtitle2">{t('incidents.suggestionsHeading')}</Typography>
          {suggestions.slice(0, 5).map((s) => (
            <Typography key={s.incident_ids.join('-')} variant="body2">
              {t(`incidents.suggestion.${s.reason}`, {
                ids: s.incident_ids.map((id) => `#${id}`).join(' · '),
                brands: s.brands.join(', '),
              })}
            </Typography>
          ))}
        </Alert>
      )}

      {loading && <CircularProgress size={24} aria-label={t('scan.loading')} />}
      {error && (
        <Alert severity="error" action={<Button color="inherit" onClick={() => setRetry((r) => r + 1)}>{t('common.retry')}</Button>}>
          {t(error)}
        </Alert>
      )}

      {!loading && !error && incidents.length === 0 && (
        <Paper variant="outlined" sx={{ p: 6, textAlign: 'center' }}>
          <Typography variant="body2" color="text.secondary">{t('incidents.noResults')}</Typography>
        </Paper>
      )}

      {!loading && !error && incidents.length > 0 && (
        <>
          <Paper variant="outlined" sx={{ overflowX: 'auto' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 600 }}>#</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{t('incidents.title')}</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{t('incidents.severity')}</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{t('incidents.status')}</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{t('incidents.findings')}</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{t('incidents.lastActivity')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {incidents.map((incident) => (
                  <TableRow key={incident.id} hover selected={selected === incident.id}
                    onClick={() => setSelected(incident.id)} sx={{ cursor: 'pointer' }}>
                    <TableCell sx={{ fontFamily: MONO_FONT, fontSize: '0.8rem' }}>{incident.id}</TableCell>
                    <TableCell>
                      {t(`soc.kind.${incident.title.split(' — ')[0].replace(/ /g, '_')}`, { defaultValue: incident.title.split(' — ')[0] })}
                      {incident.brands.length > 0 && (
                        <Typography component="span" variant="body2" color="text.secondary"> — {incident.brands.join(', ')}</Typography>
                      )}
                    </TableCell>
                    <TableCell><SeverityChip severity={incident.severity} /></TableCell>
                    <TableCell><StatusChip status={incident.status} /></TableCell>
                    <TableCell sx={{ fontFamily: MONO_FONT, fontSize: '0.8rem' }}>{incident.finding_count}</TableCell>
                    <TableCell><Timestamp value={incident.last_activity_at} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Paper>
          <Stack direction="row" useFlexGap spacing={3} sx={{ mt: 4, flexWrap: 'wrap', alignItems: 'center' }}>
            <Button size="small" disabled={offset === 0} onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}>
              {t('threats.previous')}
            </Button>
            <Button size="small" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset((o) => o + PAGE_SIZE)}>
              {t('threats.next')}
            </Button>
            <Typography variant="caption" color="text.secondary" component="span" dir="ltr" sx={{ fontFamily: MONO_FONT }}>
              {rangeStart.toLocaleString()}–{rangeEnd.toLocaleString()} / {total.toLocaleString()}
            </Typography>
          </Stack>
        </>
      )}

      {selected !== null && (
        <IncidentDetailPanel key={selected} id={selected} onChanged={() => setRetry((r) => r + 1)} onOpen={setSelected} />
      )}
    </Box>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Box sx={{ mt: 10 }}>
      <Typography variant="h4" component="h3" sx={{ mb: 3 }}>{title}</Typography>
      {children}
    </Box>
  );
}

function IncidentDetailPanel({ id, onChanged, onOpen }: { id: number; onChanged: () => void; onOpen: (id: number) => void }) {
  const { t } = useTranslation();
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loadError, setLoadError] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState('');
  const [resolution, setResolution] = useState<Resolution | ''>('');
  const [mergeInto, setMergeInto] = useState('');
  const [campaignId, setCampaignId] = useState('');
  const [newCampaign, setNewCampaign] = useState('');

  useEffect(() => {
    let cancelled = false;
    Promise.all([getIncident(id), getCampaigns()])
      .then(([incident, list]) => {
        if (!cancelled) {
          setDetail(incident);
          setCampaigns(list.results);
        }
      })
      .catch(() => {
        if (!cancelled) setLoadError(true);
      });
    return () => {
      cancelled = true;
    };
  }, [id]);

  async function run(action: () => Promise<IncidentDetail>) {
    setBusy(true);
    setActionError(null);
    try {
      const updated = await action();
      setDetail(updated);
      setNote('');
      setResolution('');
      setMergeInto('');
      setNewCampaign('');
      const list = await getCampaigns();
      setCampaigns(list.results);
      onChanged();
    } catch (err) {
      setActionError(errorCode(err));
    } finally {
      setBusy(false);
    }
  }

  if (loadError) return <Alert severity="error" sx={{ mt: 3 }}>{t('error.requestFailed')}</Alert>;
  if (!detail) return <CircularProgress size={24} sx={{ mt: 3 }} aria-label={t('scan.loading')} />;

  const trimmedNote = note.trim() || undefined;
  return (
    <Paper variant="outlined" sx={{ mt: 8, p: { xs: 4, sm: 5 }, overflowWrap: 'anywhere' }} aria-live="polite">
      <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
        <Typography variant="h6" component="h2" sx={{ marginInlineEnd: 1 }}>
          {t('incidents.detailHeading', { id: detail.id })}
        </Typography>
        <SeverityChip severity={detail.severity} />
        <StatusChip status={detail.status} />
        {detail.resolution && <Chip size="small" variant="outlined" label={t(`soc.resolution.${detail.resolution}`)} />}
        {detail.campaign && <Chip size="small" variant="outlined" label={t('incidents.campaignChip', { name: detail.campaign.name })} />}
        {detail.brands.map((b) => <Chip key={b} size="small" label={b} />)}
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
        {t('incidents.opened')}: <Timestamp value={detail.opened_at} /> · {t('incidents.lastActivity')}: <Timestamp value={detail.last_activity_at} />
        {detail.reopened_from && <> · {t('incidents.reopenedFrom')} <Button size="small" onClick={() => onOpen(detail.reopened_from!)}>#{detail.reopened_from}</Button></>}
      </Typography>
      <Alert severity="info" variant="outlined" sx={{ mt: 2 }}>{t('incidents.verdictNotice')}</Alert>

      <Section title={t('incidents.actions')}>
        {actionError && <Alert severity="error" sx={{ mb: 2 }}>{t(actionError)}</Alert>}
        <Stack spacing={2}>
          <TextField size="small" label={t('incidents.note')} value={note} multiline minRows={2}
            slotProps={{ htmlInput: { maxLength: 2000 } }} onChange={(e) => setNote(e.target.value)} />
          <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
            {detail.status === 'open' && (
              <Button variant="outlined" disabled={busy}
                onClick={() => run(() => updateIncident(id, { status: 'investigating', note: trimmedNote }))}>
                {t('incidents.startInvestigating')}
              </Button>
            )}
            {detail.status !== 'resolved' && (
              <>
                <TextField select size="small" label={t('incidents.resolution')} value={resolution} sx={{ minWidth: 170 }}
                  onChange={(e) => setResolution(e.target.value as Resolution)}>
                  {RESOLUTIONS.map((r) => <MenuItem key={r} value={r}>{t(`soc.resolution.${r}`)}</MenuItem>)}
                </TextField>
                <Button variant="contained" disabled={busy || !resolution}
                  onClick={() => run(() => updateIncident(id, { status: 'resolved', resolution: resolution as Resolution, note: trimmedNote }))}>
                  {t('incidents.resolve')}
                </Button>
              </>
            )}
            {detail.status === 'resolved' && (
              <Button variant="outlined" disabled={busy || !trimmedNote}
                onClick={() => run(() => updateIncident(id, { status: 'open', note: trimmedNote }))}>
                {t('incidents.reopen')}
              </Button>
            )}
            <Button disabled={busy || !trimmedNote} onClick={() => run(() => updateIncident(id, { note: trimmedNote }))}>
              {t('incidents.addNote')}
            </Button>
          </Stack>
          {detail.status === 'resolved' && <Typography variant="caption" color="text.secondary">{t('incidents.reopenHelp')}</Typography>}

          {detail.status !== 'resolved' && (
            <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
              <TextField size="small" label={t('incidents.mergeInto')} value={mergeInto} sx={{ width: 190 }}
                slotProps={{ htmlInput: { inputMode: 'numeric', pattern: '[0-9]*', dir: 'ltr' } }}
                onChange={(e) => setMergeInto(e.target.value.replace(/\D/g, ''))} />
              <Button disabled={busy || !mergeInto}
                onClick={() => run(() => mergeIncident(id, Number(mergeInto), trimmedNote))}>
                {t('incidents.merge')}
              </Button>
            </Stack>
          )}

          <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
            <TextField select size="small" label={t('incidents.campaign')} value={campaignId} sx={{ minWidth: 200 }}
              onChange={(e) => setCampaignId(e.target.value)}>
              {campaigns.length === 0 && <MenuItem value="" disabled>{t('incidents.noCampaigns')}</MenuItem>}
              {campaigns.map((c) => <MenuItem key={c.id} value={String(c.id)}>{c.name} ({c.incident_count})</MenuItem>)}
            </TextField>
            <Button disabled={busy || !campaignId} onClick={() => run(() => assignCampaign(Number(campaignId), id))}>
              {t('incidents.assign')}
            </Button>
            <TextField size="small" label={t('incidents.newCampaign')} value={newCampaign} sx={{ minWidth: 200 }}
              slotProps={{ htmlInput: { maxLength: 255 } }} onChange={(e) => setNewCampaign(e.target.value)} />
            <Button disabled={busy || !newCampaign.trim()}
              onClick={() => run(async () => assignCampaign((await createCampaign(newCampaign.trim())).id, id))}>
              {t('incidents.createAndAssign')}
            </Button>
          </Stack>
        </Stack>
      </Section>

      <Section title={t('incidents.timeline', { count: detail.findings.length })}>
        {detail.expired_findings > 0 && (
          <Alert severity="warning" variant="outlined" sx={{ mb: 1 }}>
            {t('incidents.expired', { count: detail.expired_findings })}
          </Alert>
        )}
        <Paper variant="outlined" sx={{ overflowX: 'auto' }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 600 }}>{t('incidents.observed')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('incidents.kind')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('incidents.severity')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('incidents.confidence')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('incidents.reasons')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {detail.findings.map((f) => (
                <TableRow key={f.id}>
                  <TableCell><Timestamp value={f.observed_at} /></TableCell>
                  <TableCell>{t(`soc.kind.${f.kind}`, { defaultValue: f.kind })}</TableCell>
                  <TableCell><SeverityChip severity={f.severity} /></TableCell>
                  <TableCell>{t(`soc.confidence.${f.confidence}`)}</TableCell>
                  <TableCell>
                    <Stack direction="row" useFlexGap sx={{ gap: 0.5, flexWrap: 'wrap' }}>
                      {f.reasons.map((r) => <Chip key={r} size="small" variant="outlined" title={r}
                        label={t(`reason.${r}`, { defaultValue: r })} />)}
                    </Stack>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      </Section>

      <Section title={t('incidents.indicators', { count: detail.indicators.length })}>
        <Typography variant="caption" color="text.secondary" component="p" sx={{ mb: 1 }}>{t('incidents.indicatorPrivacy')}</Typography>
        <Paper variant="outlined" sx={{ overflowX: 'auto' }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 600 }}>{t('soc.indicatorType')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('incidents.value')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('incidents.roles')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('incidents.sources')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {detail.indicators.map((i) => (
                <TableRow key={i.id}>
                  <TableCell>{t(`soc.type.${i.type}`)}</TableCell>
                  <TableCell>
                    {i.value ? <InertValue value={i.value} /> : <InertValue value={`sha256 ${shortHash(i.value_hash)}`} muted />}
                  </TableCell>
                  <TableCell>{i.roles.map((r) => t(`soc.role.${r}`, { defaultValue: r })).join(', ')}</TableCell>
                  <TableCell>{i.sources.map((s) => t(`soc.sourceKind.${s}`, { defaultValue: s })).join(', ')}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      </Section>

      <Section title={t('incidents.techniques')}>
        {detail.techniques.length === 0 ? (
          <Typography variant="body2" color="text.secondary">—</Typography>
        ) : (
          <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: 'wrap' }}>
            {detail.techniques.map((tech) => (
              <Chip key={`${tech.matrix}:${tech.technique_id}`} variant="outlined"
                label={<><Box component="span" dir="ltr" sx={{ fontFamily: MONO_FONT }}>{tech.technique_id}</Box>{tech.name ? ` · ${tech.name}` : ''} · {t(`soc.matrix.${tech.matrix}`)}</>} />
            ))}
          </Stack>
        )}
      </Section>

      {detail.links.length > 0 && (
        <Section title={t('incidents.related')}>
          <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: 'wrap' }}>
            {detail.links.map((l) => {
              const other = l.incident_id === detail.id ? l.related_incident_id : l.incident_id;
              return (
                <Button key={`${l.incident_id}-${l.related_incident_id}-${l.relation}`} size="small" variant="outlined" onClick={() => onOpen(other)}>
                  {t(`incidents.relation.${l.relation}`)} #{other}
                </Button>
              );
            })}
          </Stack>
        </Section>
      )}

      <Section title={t('incidents.events')}>
        <Stack divider={<Divider flexItem />} spacing={1}>
          {detail.events.map((e) => (
            <Box key={e.id}>
              <Typography variant="body2">
                <Timestamp value={e.at} /> · {t(`incidents.action.${e.action}`, { defaultValue: e.action })}
                {e.from_status && e.to_status && e.from_status !== e.to_status && (
                  <> · {t(`soc.status.${e.from_status}`)} → {t(`soc.status.${e.to_status}`)}</>
                )}
                {' · '}<Typography component="span" variant="caption" color="text.secondary">{t(`incidents.actor.${e.actor}`, { defaultValue: e.actor })}</Typography>
              </Typography>
              {e.note && e.action !== 'findings_expired' && e.action !== 'campaign_assigned' && (
                <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{e.note}</Typography>
              )}
              {e.action === 'findings_expired' && (
                <Typography variant="body2" color="text.secondary">{t('incidents.expired', { count: Number(e.note) || 0 })}</Typography>
              )}
            </Box>
          ))}
        </Stack>
      </Section>
    </Paper>
  );
}
