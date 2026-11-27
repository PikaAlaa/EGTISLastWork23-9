// "Devices" console tab with the device-risk-v1 Risk panel (design core-v2 §3.5). Read-only.
// Devices are shown only by their stored srv: pseudonym; this page never shows a computer name,
// user name, address or path. The score is a fixed count of what ETIS engines reported, not a
// verdict or a probability, and nothing on this page acts on a device.
import { useEffect, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
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
import DevicesOtherOutlinedIcon from '@mui/icons-material/DevicesOtherOutlined';
import { getDeviceRiskDetail, getDeviceRiskList } from '../api/client';
import type { DeviceRiskDetail, DeviceRiskSummary, RiskBand } from '../api/deviceRiskTypes';
import { EtisBot } from '../components/EtisBot';
import { InertValue } from '../components/InertValue';
import { RecommendedActions } from '../components/RecommendedActions';
import { ScanSurface } from '../components/ScanSurface';
import { SeverityChip, Timestamp } from '../components/SocChips';

const PAGE_SIZE = 50;

/** i18n keys may not contain dots: `malware.files` -> `malware_files`. */
const engineKey = (engine: string) => engine.replace(/\./g, '_');

function shortRef(ref: string): string {
  return ref.length > 16 ? `${ref.slice(0, 12)}…` : ref;
}

/** Navigate inside the single-page app (App listens to popstate). */
function openIncident(id: number) {
  history.pushState(null, '', `/incidents?id=${id}`);
  window.dispatchEvent(new PopStateEvent('popstate'));
}

export function DevicesPage() {
  const { t } = useTranslation();
  const [devices, setDevices] = useState<DeviceRiskSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [retry, setRetry] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(false);
    getDeviceRiskList(PAGE_SIZE, offset)
      .then((response) => {
        if (cancelled) return;
        setDevices(response.results);
        setTotal(response.total);
      })
      .catch(() => { if (!cancelled) setError(true); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [offset, retry]);

  return (
    <Box sx={{ py: 4, maxWidth: 1200, mx: 'auto' }}>
      <Typography variant="h1" component="h1" gutterBottom>{t('nav.devices')}</Typography>
      <Typography color="text.secondary" sx={{ mb: 5 }}>{t('devices.intro')}</Typography>

      {loading && <CircularProgress size={24} aria-label={t('scan.loading')} />}
      {error && (
        <Alert severity="error" action={<Button color="inherit" onClick={() => setRetry((r) => r + 1)}>{t('common.retry')}</Button>}>
          {t('error.requestFailed')}
        </Alert>
      )}

      {!loading && !error && devices.length === 0 && (
        <Paper variant="outlined" sx={{ p: 5 }}>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={4} sx={{ alignItems: 'center' }}>
            <EtisBot state="idle" size={72} />
            <Typography variant="body2" color="text.secondary">{t('devices.empty')}</Typography>
          </Stack>
        </Paper>
      )}

      {devices.length > 0 && (
        <Paper variant="outlined" sx={{ overflowX: 'auto' }}>
          <Table size="small" aria-label={t('devices.listLabel')}>
            <TableHead>
              <TableRow sx={{ bgcolor: 'action.hover' }}>
                <TableCell sx={{ fontWeight: 600 }}>{t('devices.device')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('devices.band')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('devices.points')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('devices.engines')}</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>{t('devices.lastFinding')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {devices.map((device) => (
                <TableRow key={device.device_ref} hover selected={selected === device.device_ref}
                  onClick={() => setSelected(device.device_ref)} sx={{ cursor: 'pointer' }}>
                  <TableCell>
                    <Stack spacing={0.5}>
                      <Box component="span" sx={{ whiteSpace: 'nowrap' }}><InertValue value={shortRef(device.device_ref)} /></Box>
                      {device.device_status === null && (
                        <Typography variant="caption" color="text.secondary">{t('devices.notPaired')}</Typography>
                      )}
                    </Stack>
                  </TableCell>
                  <TableCell><BandChip band={device.band} /></TableCell>
                  <TableCell><InertValue value={String(device.points)} /></TableCell>
                  <TableCell><EngineChips engines={device.engines} /></TableCell>
                  <TableCell><Timestamp value={device.last_finding_at} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Stack direction="row" sx={{ p: 3, gap: 2, flexWrap: 'wrap', alignItems: 'center', justifyContent: 'flex-end' }}>
            <Typography variant="body2" color="text.secondary">
              {t('devices.range', { from: offset + 1, to: offset + devices.length, total })}
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

      {selected !== null && <RiskPanel key={selected} deviceRef={selected} />}
    </Box>
  );
}

function BandChip({ band }: { band: RiskBand }) {
  const { t } = useTranslation();
  // A band is not a verdict, so it uses neutral styling and always shows its label.
  return <Chip size="small" variant={band === 'high' || band === 'elevated' ? 'filled' : 'outlined'}
    label={t(`devices.bandLabel.${band}`)} />;
}

function EngineChips({ engines }: { engines: string[] }) {
  const { t } = useTranslation();
  return (
    <Stack direction="row" useFlexGap sx={{ gap: 0.5, flexWrap: 'wrap' }}>
      {engines.map((e) => <Chip key={e} size="small" variant="outlined" label={t(`devices.engine.${engineKey(e)}`, { defaultValue: e })} />)}
    </Stack>
  );
}

function RiskPanel({ deviceRef }: { deviceRef: string }) {
  const { t } = useTranslation();
  const [detail, setDetail] = useState<DeviceRiskDetail | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getDeviceRiskDetail(deviceRef)
      .then((d) => { if (!cancelled) setDetail(d); })
      .catch(() => { if (!cancelled) setFailed(true); });
    return () => { cancelled = true; };
  }, [deviceRef]);

  if (failed) return <Alert severity="error" sx={{ mt: 2 }}>{t('error.requestFailed')}</Alert>;
  return (
    <Box sx={{ mt: 8 }}>
      <ScanSurface status={detail ? 'loaded' : 'scanning'} variant="radar" icon={<DevicesOtherOutlinedIcon />}
        title={<>{t('devices.riskTitle')} <InertValue value={shortRef(deviceRef)} /></>}
        statusLabel={detail ? t(`devices.bandLabel.${detail.band}`) : undefined} />
      {detail && <RiskDetail detail={detail} />}
    </Box>
  );
}

function RiskDetail({ detail }: { detail: DeviceRiskDetail }) {
  const { t } = useTranslation();
  const windows = Object.entries(detail.windows);
  return (
    <Paper variant="outlined" sx={{ mt: 3, p: { xs: 4, sm: 5 }, overflowWrap: 'anywhere' }}>
      <Typography variant="h6" component="p">
        {t('devices.total', { points: detail.points, band: t(`devices.bandLabel.${detail.band}`), days: detail.window_days,
          version: detail.version })}
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
        {t('devices.windows')}{' '}
        {windows.map(([engine, w], i) => (
          <Box component="span" key={engine}>
            {i > 0 && ' · '}
            {t(`devices.engine.${engineKey(engine)}`, { defaultValue: engine })} {t('devices.days', { count: w.days })}
            {w.setting && <> (<InertValue value={w.setting} muted />)</>}
          </Box>
        ))}
      </Typography>
      {detail.device_status === null && (
        <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 1 }}>{t('devices.notPairedNote')}</Typography>
      )}

      <Section title={t('devices.counted', { count: detail.counted.length })}>
        {detail.counted.length === 0
          ? <Typography variant="body2" color="text.secondary">{t('devices.noneCounted')}</Typography>
          : (
            <Paper variant="outlined" sx={{ overflowX: 'auto' }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 600 }}>{t('devices.engine.heading')}</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>{t('incidents.kind')}</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>{t('incidents.severity')}</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>{t('incidents.confidence')}</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>{t('devices.age')}</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>{t('devices.pointsBeforeAfter')}</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>{t('devices.incident')}</TableCell>
                    <TableCell sx={{ fontWeight: 600, minWidth: 200 }}>{t('actions.column')}</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {detail.counted.map((row) => (
                    <TableRow key={row.finding_id}>
                      <TableCell>{t(`devices.engine.${engineKey(row.engine_name)}`, { defaultValue: row.engine_name })}</TableCell>
                      <TableCell>
                        {t(`soc.kind.${row.kind}`, { defaultValue: row.kind })}
                        {row.repeats_not_counted > 0 && (
                          <Typography variant="caption" color="text.secondary" component="div">
                            {t('devices.repeats', { count: row.repeats_not_counted })}
                          </Typography>
                        )}
                        {row.from_revoked_device === true && <Chip size="small" variant="outlined" sx={{ mt: 0.5 }} label={t('devices.revoked')} />}
                      </TableCell>
                      <TableCell><SeverityChip severity={row.severity} /></TableCell>
                      <TableCell>{t(`soc.confidence.${row.confidence}`, { defaultValue: row.confidence })}</TableCell>
                      <TableCell>{t('devices.days', { count: row.age_days })}</TableCell>
                      <TableCell>
                        <InertValue value={`${row.points_before_recency} → ${row.points}`} />
                        {row.recency === 'half' && (
                          <Typography variant="caption" color="text.secondary" component="div">{t('devices.halfWeight')}</Typography>
                        )}
                      </TableCell>
                      <TableCell>
                        {row.incident_id !== null
                          ? <Link component="button" onClick={() => openIncident(row.incident_id!)}>#{row.incident_id}</Link>
                          : '—'}
                      </TableCell>
                      <TableCell>
                        <RecommendedActions actions={row.recommended_action ? [row.recommended_action] : []} compact />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Paper>
          )}
      </Section>

      {detail.cross_engine.points > 0 && (
        <Typography sx={{ mt: 4 }}>
          {t('devices.crossEngine', {
            points: detail.cross_engine.points,
            domains: detail.cross_engine.domains.map((d) => t(`soc.domain.${d}`, { defaultValue: d })).join(t('devices.and')),
          })}
        </Typography>
      )}

      {detail.not_counted.length > 0 && (
        <Section title={t('devices.notCounted', { count: detail.not_counted.length })}>
          <Stack spacing={1} component="ul" sx={{ m: 0, paddingInlineStart: 5 }}>
            {detail.not_counted.map((row) => (
              <Typography key={`${row.finding_id}-${row.reason}`} component="li" variant="body2" color="text.secondary">
                {t(`devices.engine.${engineKey(row.engine_name)}`, { defaultValue: row.engine_name })} ·{' '}
                {t(`soc.kind.${row.kind}`, { defaultValue: row.kind })} · {t('devices.days', { count: row.age_days })} —{' '}
                {t(`devices.reason.${row.reason}`, { defaultValue: row.reason, days: row.window_days })}
              </Typography>
            ))}
          </Stack>
        </Section>
      )}

      <Alert severity="info" variant="outlined" sx={{ mt: 6 }} role="note">
        <Typography variant="subtitle2" component="p" sx={{ fontWeight: 600 }}>{t('devices.aboutHeading')}</Typography>
        <Typography variant="body2">{t('devices.about')}</Typography>
      </Alert>
    </Paper>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Box sx={{ mt: 6 }}>
      <Typography variant="subtitle1" component="h3" sx={{ fontWeight: 600, mb: 2 }}>{title}</Typography>
      {children}
    </Box>
  );
}
