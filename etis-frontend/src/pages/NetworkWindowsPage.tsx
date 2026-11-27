// "Network (Windows)" console tab (design network-windows-v1 §6.7, §6.8, §7). Read-only.
// Imports start only from the local command; this page never shows a domain, address, process,
// user or computer name, or path. Commands in the help panel are inert text, never run from here.
import { useEffect, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Divider,
  Link,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';

import { getNetworkHealth, getNetworkImport, getNetworkImports } from '../api/client';
import type {
  Coverage,
  DetectionState,
  ListAttribution,
  NetworkFinding,
  NetworkHealth,
  NetworkImportDetail,
  NetworkImportSummary,
} from '../api/networkTypes';
import DetailIcon from '@mui/icons-material/Lan';
import { ScanSurface } from '../components/ScanSurface';
import { detailStatus } from '../components/detailStatus';
import { InertValue } from '../components/InertValue';
import { SeverityChip, Timestamp } from '../components/SocChips';

const MONO_FONT = "'IBM Plex Mono', monospace";
const PAGE_SIZE = 20;
const DETECTIONS = ['N1', 'N2', 'N3', 'N4', 'N5', 'N6', 'N7', 'N8', 'N9'] as const;
const SOURCES = ['dns_client', 'sysmon22', 'firewall', 'sysmon3', 'snapshot'] as const;
// Attribution links are shown only for the v1 list page (design §2.2 and its note of 27 November 2026).
const LIST_LINKS = new Set(['https://feodotracker.abuse.ch/blocklist/']);
const IMPORT_COMMAND =
  'python data/scripts/import_network_windows.py --dns-evtx C:\\exports\\dns.evtx [--firewall-log C:\\exports\\pfirewall.log] [--sysmon-evtx C:\\exports\\sysmon.evtx] [--snapshots var\\network-snapshots\\<file>.jsonl] [--local-net 192.168.1.0/24]';
const HELP_COMMANDS: { key: string; command?: string }[] = [
  { key: 'dns', command: 'wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true' },
  { key: 'dnsSize', command: 'wevtutil sl Microsoft-Windows-DNS-Client/Operational /ms:<bytes>' },
  { key: 'dnsExport', command: 'wevtutil epl Microsoft-Windows-DNS-Client/Operational C:\\exports\\dns.evtx' },
  { key: 'firewall' },
  { key: 'sysmon' },
  { key: 'snapshot', command: 'python data/scripts/snapshot_connections.py' },
];
const STATE_COLOR: Record<DetectionState, 'success' | 'warning' | 'error' | 'default'> = {
  visible: 'success',
  partial: 'warning',
  not_visible: 'error',
  no_baseline: 'default',
  inactive: 'default',
};

/** Navigate inside the single-page app (App listens to popstate). */
function openIncident(id: number) {
  history.pushState(null, '', `/incidents?id=${id}`);
  window.dispatchEvent(new PopStateEvent('popstate'));
}

export function NetworkWindowsPage() {
  const { t } = useTranslation();
  const [health, setHealth] = useState<NetworkHealth | null>(null);
  const [imports, setImports] = useState<NetworkImportSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [retry, setRetry] = useState(0);
  const [selected, setSelected] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    getNetworkHealth().then((h) => { if (!cancelled) setHealth(h); }).catch(() => { if (!cancelled) setHealth(null); });
    return () => { cancelled = true; };
  }, [retry]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(false);
    getNetworkImports(PAGE_SIZE, offset)
      .then((response) => {
        if (cancelled) return;
        setImports(response.results);
        setTotal(response.total_matching);
      })
      .catch(() => { if (!cancelled) setError(true); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [offset, retry]);

  return (
    <Box sx={{ py: 4, maxWidth: 1200, mx: 'auto' }}>
      <Typography variant="h1" component="h1" gutterBottom>{t('nav.network')}</Typography>
      <Typography color="text.secondary" sx={{ mb: 5 }}>{t('network.intro')}</Typography>

      {health && <HealthBanner health={health} />}

      {loading && <CircularProgress size={24} aria-label={t('scan.loading')} />}
      {error && (
        <Alert severity="error" action={<Button color="inherit" onClick={() => setRetry((r) => r + 1)}>{t('common.retry')}</Button>}>
          {t('error.requestFailed')}
        </Alert>
      )}

      {!loading && !error && imports.length === 0 && (
        <Paper variant="outlined" sx={{ p: 5, textAlign: 'center' }}>
          <Typography variant="body2" color="text.secondary">{t('network.noImports')}</Typography>
          <Box sx={{ mt: 1 }}><InertValue value={IMPORT_COMMAND} /></Box>
        </Paper>
      )}

      {imports.length > 0 && (
        <Paper variant="outlined" sx={{ overflowX: 'auto' }}>
          <Table size="small" aria-label={t('network.imports')}>
            <TableHead>
              <TableRow sx={{ bgcolor: 'action.hover' }}>
                <TableCell sx={{ fontWeight: 600 }}>#</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('network.started')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('network.span')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('network.sources')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('network.findings')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {imports.map((item) => (
                <TableRow key={item.id} hover selected={selected === item.id} onClick={() => setSelected(item.id)}
                  sx={{ cursor: 'pointer' }}>
                  <TableCell sx={{ fontFamily: MONO_FONT, fontSize: '0.8rem' }}>{item.id}</TableCell>
                  <TableCell><Timestamp value={item.started_at} /></TableCell>
                  <TableCell>
                    <Timestamp value={item.span_first} />{' – '}<Timestamp value={item.span_last} />
                  </TableCell>
                  <TableCell><SourceChips coverage={item.coverage} /></TableCell>
                  <TableCell><KindCounts counts={item.findings_by_kind} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Stack direction="row" sx={{ p: 3, gap: 2, flexWrap: 'wrap', alignItems: 'center', justifyContent: 'flex-end' }}>
            <Typography variant="body2" color="text.secondary">
              {t('network.range', { from: offset + 1, to: offset + imports.length, total })}
            </Typography>
            <Button size="small" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
              {t('network.previous')}
            </Button>
            <Button size="small" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>
              {t('network.next')}
            </Button>
          </Stack>
        </Paper>
      )}

      {selected !== null && <ImportDetailPanel key={selected} id={selected} />}
      <HelpPanel />
    </Box>
  );
}

function HealthBanner({ health }: { health: NetworkHealth }) {
  const { t } = useTranslation();
  const severity = !health.available ? 'error' : health.reasons.length ? 'warning' : 'success';
  return (
    <Alert severity={severity} sx={{ mb: 4 }}>
      <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
        <span>{health.available ? t('network.health.available') : t('network.health.unavailable')}</span>
        {health.reasons.map((reason) => (
          <Chip key={reason} size="small" variant="outlined" label={t(`network.health.${reason}`)} />
        ))}
        {health.rules_detail && (
          <Chip size="small" variant="outlined" label={t(`network.rulesDetail.${health.rules_detail}`)} />
        )}
        <InertValue value={health.version} muted />
      </Stack>
    </Alert>
  );
}

function HelpPanel() {
  const { t } = useTranslation();
  return (
    <Paper variant="outlined" sx={{ p: 4, mt: 12 }}>
      <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>{t('network.help.title')}</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{t('network.help.ownerOnly')}</Typography>
      <Stack sx={{ gap: 1 }}>
        {HELP_COMMANDS.map(({ key, command }) => (
          <Box key={key}>
            <Typography variant="body2">{t(`network.help.${key}`)}</Typography>
            {command && <InertValue value={command} />}
          </Box>
        ))}
        <Box>
          <Typography variant="body2">{t('network.help.import')}</Typography>
          <InertValue value={IMPORT_COMMAND} />
        </Box>
      </Stack>
      <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 1 }}>{t('network.help.privacy')}</Typography>
    </Paper>
  );
}

function SourceChips({ coverage }: { coverage: Coverage }) {
  const { t } = useTranslation();
  const present = SOURCES.filter((name) => (coverage.sources?.[name]?.records ?? 0) > 0);
  if (present.length === 0) return <Typography variant="body2" color="text.secondary">{t('network.none')}</Typography>;
  return (
    <Stack direction="row" useFlexGap sx={{ gap: 0.5, flexWrap: 'wrap' }}>
      {present.map((name) => <Chip key={name} size="small" variant="outlined" label={t(`network.source.${name}`)} />)}
    </Stack>
  );
}

function KindCounts({ counts }: { counts: NetworkImportSummary['findings_by_kind'] }) {
  const { t } = useTranslation();
  const entries = Object.entries(counts).filter(([, n]) => (n ?? 0) > 0);
  if (entries.length === 0) return <Typography variant="body2" color="text.secondary">{t('network.none')}</Typography>;
  return (
    <Stack direction="row" useFlexGap sx={{ gap: 0.5, flexWrap: 'wrap' }}>
      {entries.map(([kind, n]) => <Chip key={kind} size="small" variant="outlined" label={`${t(`soc.kind.${kind}`)} · ${n}`} />)}
    </Stack>
  );
}

function ImportDetailPanel({ id }: { id: number }) {
  const { t } = useTranslation();
  const [detail, setDetail] = useState<NetworkImportDetail | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getNetworkImport(id).then((d) => { if (!cancelled) setDetail(d); }).catch(() => { if (!cancelled) setFailed(true); });
    return () => { cancelled = true; };
  }, [id]);

  if (failed) return <Alert severity="error" sx={{ mt: 2 }}>{t('error.requestFailed')}</Alert>;
  const { severity, status } = detailStatus(detail);
  return (
    <Box sx={{ mt: 8 }}>
      <ScanSurface status={status} variant="radar" icon={<DetailIcon />} title={t('network.importTitle', { id })}
        statusLabel={severity ? t('scan.highestSeverity', { severity: t(`soc.severity.${severity}`) }) : undefined} />
      {detail && <ImportDetail detail={detail} />}
    </Box>
  );
}

function ImportDetail({ detail }: { detail: NetworkImportDetail }) {
  const { t } = useTranslation();
  return (
    <Paper variant="outlined" sx={{ mt: 3, p: { xs: 4, sm: 5 }, overflowWrap: 'anywhere' }}>
      <Stack direction="row" useFlexGap sx={{ gap: 2, flexWrap: 'wrap', mb: 1 }}>
        <Field label={t('network.started')}><Timestamp value={detail.started_at} /></Field>
        <Field label={t('network.span')}>
          <Timestamp value={detail.span_first} />{' – '}<Timestamp value={detail.span_last} />
        </Field>
        <Field label={t('network.engineVersion')}><InertValue value={detail.engine_version} /></Field>
      </Stack>
      <CoveragePanel coverage={detail.coverage} />
      <Typography variant="subtitle2" sx={{ mt: 2 }}>{t('network.files')}</Typography>
      <Stack sx={{ gap: 0.5, mb: 1 }}>
        {detail.files.map((file) => (
          <Box key={`${file.source}:${file.sha256}`} sx={{ fontSize: '0.875rem' }}>
            {t(`network.fileSource.${file.source}`)} · {t('network.records', { n: file.records })} ·{' '}
            <InertValue value={`sha256:${file.sha256.slice(0, 16)}…`} muted />
          </Box>
        ))}
      </Stack>
      <Divider sx={{ my: 2 }} />
      {detail.findings.length === 0 && <Typography variant="body2" color="text.secondary">{t('network.noFindings')}</Typography>}
      <Stack sx={{ gap: 2 }}>
        {detail.findings.map((finding) => <FindingCard key={finding.id} finding={finding} />)}
      </Stack>
    </Paper>
  );
}

function CoveragePanel({ coverage }: { coverage: Coverage }) {
  const { t } = useTranslation();
  const states = coverage.detections ?? {};
  const notRun = coverage.not_run ?? {};
  return (
    <Box sx={{ mt: 1 }}>
      <Typography variant="subtitle2">{t('network.coverage')}</Typography>
      <Typography variant="caption" color="text.secondary" component="p" sx={{ mb: 0.5 }}>{t('network.coverageNote')}</Typography>
      <Stack direction="row" useFlexGap sx={{ gap: 0.5, flexWrap: 'wrap' }}>
        {DETECTIONS.map((id) => {
          const state = (states[id] ?? 'not_visible') as DetectionState;
          const reason = notRun[id];
          return (
            <Chip key={id} size="small" color={STATE_COLOR[state]} variant={state === 'visible' ? 'filled' : 'outlined'}
              label={`${id} · ${t(`network.detection.${id}`)} · ${t(`network.state.${state}`)}${reason ? ` · ${t(`network.notRun.${reason}`)}` : ''}`} />
          );
        })}
      </Stack>
      <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 0.5 }}>
        {t('network.baseline', { value: coverage.baseline ?? 'none' })}
      </Typography>
    </Box>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Box>
      <Typography variant="caption" color="text.secondary" component="div">{label}</Typography>
      <Box sx={{ fontSize: '0.875rem' }}>{children}</Box>
    </Box>
  );
}

function FindingCard({ finding }: { finding: NetworkFinding }) {
  const { t } = useTranslation();
  const values = Object.entries(finding.values ?? {});
  return (
    <Paper variant="outlined" sx={{ p: 4, overflowWrap: 'anywhere' }}>
      <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: 'wrap', alignItems: 'center', mb: 1.5 }}>
        <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>{t(`soc.kind.${finding.kind}`)}</Typography>
        <SeverityChip severity={finding.severity} />
        <Chip size="small" variant="outlined" label={t(`soc.confidence.${finding.confidence}`)} />
        {finding.detection && <Chip size="small" label={`${finding.detection} · ${t(`network.detection.${finding.detection}`)}`} />}
        {finding.rule_validation === 'unvalidated_on_samples' && (
          <Chip size="small" color="warning" variant="outlined" label={t('network.unvalidated')} />
        )}
        <Box sx={{ flexGrow: 1 }} />
        {finding.incident_id !== null ? (
          <Button size="small" variant="outlined" onClick={() => openIncident(finding.incident_id as number)}>
            {t('network.openIncident', { id: finding.incident_id })}
          </Button>
        ) : (
          <Typography variant="caption" color="text.secondary">{t('network.noIncident')}</Typography>
        )}
      </Stack>

      <Stack direction="row" useFlexGap sx={{ gap: 0.5, flexWrap: 'wrap', mb: 1.5 }}>
        {(finding.reason_codes ?? finding.reasons).map((code) => (
          <Chip key={code} size="small" variant="outlined" label={t(`network.reason.${code}`)} />
        ))}
      </Stack>

      <Stack direction="row" useFlexGap sx={{ gap: 3, flexWrap: 'wrap', mb: 1.5 }}>
        <Field label={t('network.window')}>
          <Timestamp value={finding.window.first} />{' – '}<Timestamp value={finding.window.last} />
        </Field>
        <Field label={t('network.events')}>{finding.events ?? '—'}</Field>
        <Field label={t('network.device')}>{finding.device_ref ? <InertValue value={finding.device_ref} /> : '—'}</Field>
        <Field label={t('network.process')}>{t(`network.processCategory.${finding.process_category ?? 'unknown'}`)}</Field>
        <Field label={t('network.combinedWith')}>{finding.combined_with?.length ? finding.combined_with.join(', ') : '—'}</Field>
      </Stack>

      {values.length > 0 && (
        <Stack direction="row" useFlexGap sx={{ gap: 0.5, flexWrap: 'wrap', mb: 1 }}>
          {values.map(([key, value]) => <InertChip key={key} text={`${key}: ${value}`} />)}
        </Stack>
      )}

      {finding.lists.length > 0 && (
        <>
          <Typography variant="subtitle2" sx={{ mt: 1 }}>{t('network.lists')}</Typography>
          <Stack sx={{ gap: 0.5, my: 0.5 }}>
            {finding.lists.map((list) => <ListLine key={list.list} list={list} />)}
          </Stack>
        </>
      )}

      {finding.attack.length > 0 && (
        <>
          <Typography variant="subtitle2" sx={{ mt: 1 }}>ATT&CK</Typography>
          <Stack direction="row" useFlexGap sx={{ gap: 0.5, flexWrap: 'wrap' }}>
            {finding.attack.map((a) => (
              <Chip key={a.technique_id} size="small" variant="outlined"
                label={a.name ? `${a.technique_id} · ${a.name}` : a.technique_id} />
            ))}
          </Stack>
        </>
      )}
    </Paper>
  );
}

function InertChip({ text }: { text: string }) {
  return <Chip size="small" variant="outlined" label={<InertValue value={text} />} />;
}

function ListLine({ list }: { list: ListAttribution }) {
  const { t } = useTranslation();
  return (
    <Box sx={{ fontSize: '0.875rem' }}>
      <bdi>{list.title}</bdi>
      {' · '}{t('network.listVersion')}: <InertValue value={list.version} />
      {' · '}{t('network.listLicence')}: <bdi>{list.licence}</bdi>
      {' · '}
      {LIST_LINKS.has(list.link) ? (
        <Link href={list.link} target="_blank" rel="noopener noreferrer">{t('network.listPage')}</Link>
      ) : (
        <InertValue value={list.link} />
      )}
    </Box>
  );
}
