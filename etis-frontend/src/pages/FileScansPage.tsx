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

import { getMalwareHealth, getMalwareScan, getMalwareScans } from '../api/client';
import type { MalwareFinding, MalwareHealth, MalwareScanDetail, MalwareScanSummary, YaraRuleMatch } from '../api/malwareTypes';
import { InertValue } from '../components/InertValue';
import { SeverityChip, Timestamp } from '../components/SocChips';

const MONO_FONT = "'IBM Plex Mono', monospace";
const PAGE_SIZE = 20;
// Attribution links are shown only for the pinned signature-base repository (design §3.6, §6.6).
const RULE_LINK = /^https:\/\/github\.com\/Neo23x0\/signature-base\/blob\/[0-9a-f]{40}\/[A-Za-z0-9_./-]+#L\d+$/;
const FIND_COMMAND = 'python data/scripts/scan_files.py --find <path_ref> --path <folder>';

/** Navigate inside the single-page app (App listens to popstate). */
function openIncident(id: number) {
  history.pushState(null, '', `/incidents?id=${id}`);
  window.dispatchEvent(new PopStateEvent('popstate'));
}

export function FileScansPage() {
  const { t } = useTranslation();
  const [health, setHealth] = useState<MalwareHealth | null>(null);
  const [scans, setScans] = useState<MalwareScanSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [retry, setRetry] = useState(0);
  const [selected, setSelected] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    getMalwareHealth().then((h) => { if (!cancelled) setHealth(h); }).catch(() => { if (!cancelled) setHealth(null); });
    return () => { cancelled = true; };
  }, [retry]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(false);
    getMalwareScans(PAGE_SIZE, offset)
      .then((response) => {
        if (cancelled) return;
        setScans(response.results);
        setTotal(response.total_matching);
      })
      .catch(() => { if (!cancelled) setError(true); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [offset, retry]);

  return (
    <Box sx={{ py: 4, maxWidth: 1200, mx: 'auto' }}>
      <Typography variant="h5" component="h1" gutterBottom>{t('nav.files')}</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{t('files.intro')}</Typography>

      {health && <HealthBanner health={health} />}

      <Alert severity="info" variant="outlined" sx={{ mb: 2 }}>
        {t('files.findHelp')}{' '}
        <InertValue value={FIND_COMMAND} />
      </Alert>

      {loading && <CircularProgress size={24} aria-label={t('scan.loading')} />}
      {error && (
        <Alert severity="error" action={<Button color="inherit" onClick={() => setRetry((r) => r + 1)}>{t('common.retry')}</Button>}>
          {t('error.requestFailed')}
        </Alert>
      )}

      {!loading && !error && scans.length === 0 && (
        <Paper variant="outlined" sx={{ p: 3, borderRadius: 3, textAlign: 'center' }}>
          <Typography variant="body2" color="text.secondary">{t('files.noScans')}</Typography>
          <Box sx={{ mt: 1 }}><InertValue value="python data/scripts/scan_files.py --path <folder> --recursive" /></Box>
        </Paper>
      )}

      {scans.length > 0 && (
        <Paper variant="outlined" sx={{ borderRadius: 3, overflowX: 'auto' }}>
          <Table size="small" aria-label={t('files.scans')}>
            <TableHead>
              <TableRow sx={{ bgcolor: 'action.hover' }}>
                <TableCell sx={{ fontWeight: 600 }}>#</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('files.started')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('files.peFiles')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('files.findings')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('files.model')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {scans.map((scan) => (
                <TableRow key={scan.id} hover selected={selected === scan.id} onClick={() => setSelected(scan.id)}
                  sx={{ cursor: 'pointer' }}>
                  <TableCell sx={{ fontFamily: MONO_FONT, fontSize: '0.8rem' }}>{scan.id}</TableCell>
                  <TableCell><Timestamp value={scan.started_at} /></TableCell>
                  <TableCell sx={{ fontFamily: MONO_FONT, fontSize: '0.8rem' }}>{scan.counts.walk?.pe ?? 0}</TableCell>
                  <TableCell><KindCounts counts={scan.findings_by_kind} /></TableCell>
                  <TableCell><InertValue value={scan.model_id} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Stack direction="row" sx={{ p: 1, gap: 1, alignItems: 'center', justifyContent: 'flex-end' }}>
            <Typography variant="body2" color="text.secondary">
              {t('files.range', { from: offset + 1, to: offset + scans.length, total })}
            </Typography>
            <Button size="small" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
              {t('files.previous')}
            </Button>
            <Button size="small" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>
              {t('files.next')}
            </Button>
          </Stack>
        </Paper>
      )}

      {selected !== null && <ScanDetailPanel key={selected} id={selected} />}
    </Box>
  );
}

function HealthBanner({ health }: { health: MalwareHealth }) {
  const { t } = useTranslation();
  const severity = !health.available ? 'error' : health.reasons.length ? 'warning' : 'success';
  return (
    <Alert severity={severity} sx={{ mb: 2 }}>
      <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
        <span>{health.available ? t('files.health.available') : t('files.health.unavailable')}</span>
        {health.reasons.map((reason) => <Chip key={reason} size="small" variant="outlined" label={t(`files.health.${reason}`)} />)}
        <Chip size="small" label={`${t('files.model')}: ${health.model}`} />
      </Stack>
    </Alert>
  );
}

function KindCounts({ counts }: { counts: MalwareScanSummary['findings_by_kind'] }) {
  const { t } = useTranslation();
  const entries = Object.entries(counts).filter(([, n]) => (n ?? 0) > 0);
  if (entries.length === 0) return <Typography variant="body2" color="text.secondary">{t('files.none')}</Typography>;
  return (
    <Stack direction="row" useFlexGap sx={{ gap: 0.5, flexWrap: 'wrap' }}>
      {entries.map(([kind, n]) => <Chip key={kind} size="small" variant="outlined" label={`${t(`soc.kind.${kind}`)} · ${n}`} />)}
    </Stack>
  );
}

function ScanDetailPanel({ id }: { id: number }) {
  const { t } = useTranslation();
  const [detail, setDetail] = useState<MalwareScanDetail | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getMalwareScan(id).then((d) => { if (!cancelled) setDetail(d); }).catch(() => { if (!cancelled) setFailed(true); });
    return () => { cancelled = true; };
  }, [id]);

  if (failed) return <Alert severity="error" sx={{ mt: 2 }}>{t('error.requestFailed')}</Alert>;
  if (!detail) return <CircularProgress size={24} sx={{ mt: 2 }} aria-label={t('scan.loading')} />;
  const walk = detail.counts.walk ?? {};
  return (
    <Paper variant="outlined" sx={{ mt: 3, p: 3, borderRadius: 3 }}>
      <Typography variant="h6" gutterBottom>{t('files.scanTitle', { id: detail.id })}</Typography>
      <Stack direction="row" useFlexGap sx={{ gap: 2, flexWrap: 'wrap', mb: 1 }}>
        <Field label={t('files.started')}><Timestamp value={detail.started_at} /></Field>
        <Field label={t('files.finished')}><Timestamp value={detail.finished_at} /></Field>
        <Field label={t('files.engineVersion')}><InertValue value={detail.engine_version} /></Field>
      </Stack>
      <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: 'wrap', mb: 2 }}>
        {(['files_seen', 'pe', 'not_pe', 'too_large', 'unreadable', 'reparse_point'] as const).map((key) => (
          <Chip key={key} size="small" variant="outlined" label={`${t(`files.count.${key}`)}: ${walk[key] ?? 0}`} />
        ))}
      </Stack>
      <Divider sx={{ mb: 2 }} />
      {detail.findings.length === 0 && <Typography variant="body2" color="text.secondary">{t('files.noFindings')}</Typography>}
      <Stack sx={{ gap: 2 }}>
        {detail.findings.map((finding) => <FindingCard key={finding.id} finding={finding} />)}
      </Stack>
    </Paper>
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

function FindingCard({ finding }: { finding: MalwareFinding }) {
  const { t } = useTranslation();
  const model = finding.layers.model as MalwareFinding['layers']['model'] & { status?: string };
  return (
    <Paper variant="outlined" sx={{ p: 2, borderRadius: 2 }}>
      <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: 'wrap', alignItems: 'center', mb: 1.5 }}>
        <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>{t(`soc.kind.${finding.kind}`)}</Typography>
        <SeverityChip severity={finding.severity} />
        <Chip size="small" variant="outlined" label={t(`soc.confidence.${finding.confidence}`)} />
        {finding.known_software_conflict && <Chip size="small" color="warning" label={t('files.conflict')} />}
        <Box sx={{ flexGrow: 1 }} />
        {finding.incident_id !== null ? (
          <Button size="small" variant="outlined" onClick={() => openIncident(finding.incident_id as number)}>
            {t('files.openIncident', { id: finding.incident_id })}
          </Button>
        ) : (
          <Typography variant="caption" color="text.secondary">{t('files.noIncident')}</Typography>
        )}
      </Stack>

      <Stack direction="row" useFlexGap sx={{ gap: 3, flexWrap: 'wrap', mb: 1.5 }}>
        <Field label="path_ref">{finding.path_ref ? <InertValue value={finding.path_ref} /> : '—'}</Field>
        <Field label={t('files.location')}>{finding.location_class ? t(`files.locationClass.${finding.location_class}`) : '—'}</Field>
        <Field label={t('files.extension')}><InertValue value={finding.extension || '—'} /></Field>
        <Field label={t('files.sizeBand')}>{finding.size_band ? t(`files.size.${finding.size_band}`) : '—'}</Field>
        <Field label={t('files.peType')}>{finding.pe_type ? t(`files.pe.${finding.pe_type}`) : '—'}</Field>
        <Field label={t('files.pathCount')}>{finding.path_count ?? '—'}</Field>
        <Field label={t('files.signature')}>
          {finding.signature_present ? t('files.signaturePresent') : t('files.signatureAbsent')}
        </Field>
      </Stack>

      <Typography variant="subtitle2" sx={{ mt: 1 }}>{t('files.layer.hash')}</Typography>
      {finding.layers.hash_lists.lists.length === 0 ? (
        <Typography variant="body2" color="text.secondary">{t('files.health.hashlists_missing')}</Typography>
      ) : (
        <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: 'wrap', my: 0.5 }}>
          {finding.layers.hash_lists.lists.map((list) => (
            <Chip key={list.name} size="small" color={list.match ? (list.role === 'malicious' ? 'error' : 'info') : 'default'}
              variant={list.match ? 'filled' : 'outlined'}
              label={`${list.name} ${list.version} · ${t(`files.role.${list.role}`)} · ${list.match ? t('files.match') : t('files.noMatch')}`} />
          ))}
        </Stack>
      )}

      <Typography variant="subtitle2" sx={{ mt: 1 }}>{t('files.layer.yara')}</Typography>
      {finding.layers.yara.rules.length === 0 ? (
        <Typography variant="body2" color="text.secondary">{t('files.noRules')}</Typography>
      ) : (
        <Stack sx={{ gap: 0.5, my: 0.5 }}>
          {finding.layers.yara.rules.map((rule) => <RuleLine key={`${rule.rule_file}:${rule.rule}`} rule={rule} />)}
        </Stack>
      )}

      <Typography variant="subtitle2" sx={{ mt: 1 }}>{t('files.layer.model')}</Typography>
      <Typography variant="body2" color="text.secondary">
        {model.status === 'model_none' || !model.status
          ? t('files.health.model_none')
          : t('files.modelLine', {
            id: model.model_id, status: model.status, score: model.score ?? '—', threshold: model.threshold ?? '—',
            parity: model.parity ?? '—',
          })}
      </Typography>

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

function RuleLine({ rule }: { rule: YaraRuleMatch }) {
  const { t } = useTranslation();
  return (
    <Box sx={{ fontSize: '0.875rem' }}>
      <Box component="span" dir="ltr" sx={{ fontFamily: MONO_FONT, fontWeight: 600 }}>{rule.rule}</Box>
      {' — '}{t('files.ruleAuthor')}: <bdi>{rule.author || '—'}</bdi>
      {' · '}{t('files.ruleSource')}: <bdi>{rule.source}</bdi>
      {' · '}{t('files.ruleLicence')}: <bdi>{rule.licence}</bdi>
      {' · '}
      {RULE_LINK.test(rule.link) ? (
        <Link href={rule.link} target="_blank" rel="noopener noreferrer">
          {t('files.ruleLink', { commit: rule.pinned_commit.slice(0, 12) })}
        </Link>
      ) : (
        <InertValue value={rule.link} />
      )}
    </Box>
  );
}
