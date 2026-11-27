import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Alert,
  Box,
  Button,
  ButtonBase,
  Chip,
  CircularProgress,
  FormControlLabel,
  Paper,
  Stack,
  Switch,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
} from '@mui/material';

import { getAttackCoverage, getAttackTechnique } from '../api/client';
import type { AttackCoverage, AttackMatrix, AttackTechniqueDetail, CoverageCell } from '../api/socTypes';
import { InertValue } from '../components/InertValue';
import { SeverityChip, StatusChip } from '../components/SocChips';

const MONO_FONT = "'IBM Plex Mono', monospace";

function heat(count: number, max: number): string {
  if (count === 0 || max === 0) return 'transparent';
  return `color-mix(in srgb, var(--etis-accent) ${10 + 25 * count / max}%, var(--etis-surface))`;
}

export function AttackPage() {
  const { t } = useTranslation();
  const [matrix, setMatrix] = useState<AttackMatrix>('enterprise');
  const [since, setSince] = useState('');
  const [until, setUntil] = useState('');
  const [observedOnly, setObservedOnly] = useState(true);
  const [coverage, setCoverage] = useState<AttackCoverage | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [retry, setRetry] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(false);
    getAttackCoverage(matrix, since || undefined, until || undefined)
      .then((response) => {
        if (!cancelled) setCoverage(response);
      })
      .catch(() => {
        if (!cancelled) setError(true);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [matrix, since, until, retry]);

  const max = useMemo(
    () => Math.max(0, ...(coverage?.tactics.flatMap((tactic) => tactic.techniques.map((cell) => cell.findings)) ?? [])),
    [coverage],
  );
  const columns = (coverage?.tactics ?? [])
    .map((tactic) => ({ ...tactic, techniques: observedOnly ? tactic.techniques.filter((c) => c.findings > 0) : tactic.techniques }))
    .filter((tactic) => tactic.techniques.length > 0);

  return (
    <Box>
      <Typography variant="h1" component="h1" gutterBottom>{t('nav.attack')}</Typography>
      <Typography color="text.secondary" sx={{ mb: 5 }}>{t('attack.intro')}</Typography>

      <Paper variant="outlined" className="etis-filters">
        <ToggleButtonGroup exclusive size="small" value={matrix} aria-label={t('attack.matrix')}
          onChange={(_, value: AttackMatrix | null) => { if (value) { setMatrix(value); setSelected(null); } }}>
          <ToggleButton value="enterprise">{t('soc.matrix.enterprise')}</ToggleButton>
          <ToggleButton value="mobile">{t('soc.matrix.mobile')}</ToggleButton>
        </ToggleButtonGroup>
        <TextField size="small" type="date" label={t('incidents.since')} value={since}
          slotProps={{ inputLabel: { shrink: true } }} onChange={(e) => setSince(e.target.value)} />
        <TextField size="small" type="date" label={t('incidents.until')} value={until}
          slotProps={{ inputLabel: { shrink: true } }} onChange={(e) => setUntil(e.target.value)} />
        <FormControlLabel control={<Switch checked={observedOnly} onChange={(e) => setObservedOnly(e.target.checked)} />}
          label={t('attack.observedOnly')} />
        {coverage && (
          <Typography variant="body2" color="text.secondary">
            <Box component="span" sx={{ fontFamily: MONO_FONT }}>{coverage.total_findings.toLocaleString()}</Box>{' '}
            {t('attack.mappedFindings')}
          </Typography>
        )}
      </Paper>

      {loading && <CircularProgress size={24} aria-label={t('scan.loading')} />}
      {error && (
        <Alert severity="error" action={<Button color="inherit" onClick={() => setRetry((r) => r + 1)}>{t('common.retry')}</Button>}>
          {t('error.requestFailed')}
        </Alert>
      )}

      {coverage && !coverage.installed && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          {t('attack.notInstalled')}{' '}
          <InertValue value="python data/scripts/fetch_attack.py && python scripts/initialize.py" />
        </Alert>
      )}

      {coverage && coverage.installed && !loading && columns.length === 0 && (
        <Paper variant="outlined" sx={{ p: 6, textAlign: 'center' }}>
          <Typography variant="body2" color="text.secondary">{t('attack.noFindings')}</Typography>
        </Paper>
      )}

      {coverage && columns.length > 0 && (
        <Paper variant="outlined" sx={{ overflowX: 'auto' }}>
          <Box sx={{ display: 'flex', gap: 4, p: 4, minWidth: 'min-content' }} role="region" aria-label={t('attack.gridLabel')}>
            {columns.map((column) => (
              <Box key={column.tactic} sx={{ width: 216, flexShrink: 0 }}>
                <Typography variant="caption" component="h3"
                  sx={{ fontWeight: 600, p: 3, bgcolor: 'var(--etis-surface2)', borderRadius: 1, mb: 2 }}>
                  {t(`attack.tactic.${column.tactic}`, { defaultValue: column.tactic })}
                  <Box component="span" sx={{ color: 'text.secondary', fontWeight: 400 }}> ({column.techniques.length})</Box>
                </Typography>
                <Stack spacing={0.5}>
                  {column.techniques.map((cell) => (
                    <TechniqueCell key={cell.technique_id} cell={cell} max={max} selected={selected === cell.technique_id}
                      onSelect={() => setSelected(cell.technique_id)} />
                  ))}
                </Stack>
              </Box>
            ))}
          </Box>
        </Paper>
      )}

      {coverage && coverage.uncatalogued.length > 0 && (
        <Alert severity="info" sx={{ mt: 2 }}>
          {t('attack.uncatalogued')}{' '}
          {coverage.uncatalogued.map((u) => <InertValue key={u.technique_id} value={`${u.technique_id} (${u.findings}) `} />)}
        </Alert>
      )}

      {selected && <TechniquePanel key={`${matrix}:${selected}`} techniqueId={selected} matrix={matrix} />}

      {coverage && (
        <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 3 }}>
          {t('attack.dataSource', { version: coverage.attack_version })}{' '}
          <Box component="span" dir="ltr">{coverage.copyright}</Box>
        </Typography>
      )}
    </Box>
  );
}

function TechniqueCell({ cell, max, selected, onSelect }: { cell: CoverageCell; max: number; selected: boolean; onSelect: () => void }) {
  const { t } = useTranslation();
  return (
    <ButtonBase onClick={onSelect} aria-pressed={selected}
      aria-label={t('attack.cellLabel', { id: cell.technique_id, name: cell.name, count: cell.findings })}
      sx={{
        display: 'block', textAlign: 'start', width: '100%', p: 3, borderRadius: 1,
        border: 1, borderColor: selected ? 'primary.main' : 'divider', bgcolor: heat(cell.findings, max),
      }}>
      <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'baseline', gap: 1 }}>
        <Box component="span" dir="ltr" sx={{ fontFamily: MONO_FONT, fontSize: '0.75rem' }}>{cell.technique_id}</Box>
        {cell.findings > 0 && (
          <Box component="span" sx={{ fontFamily: MONO_FONT, fontSize: '0.75rem', fontWeight: 600 }}>{cell.findings}</Box>
        )}
      </Stack>
      <Typography variant="caption" component="div" dir="ltr" sx={{ lineHeight: 1.3 }}>{cell.name}</Typography>
    </ButtonBase>
  );
}

function TechniquePanel({ techniqueId, matrix }: { techniqueId: string; matrix: AttackMatrix }) {
  const { t } = useTranslation();
  const [detail, setDetail] = useState<AttackTechniqueDetail | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getAttackTechnique(techniqueId, matrix)
      .then((response) => { if (!cancelled) setDetail(response); })
      .catch(() => { if (!cancelled) setFailed(true); });
    return () => {
      cancelled = true;
    };
  }, [techniqueId, matrix]);

  if (failed) return <Alert severity="error" sx={{ mt: 3 }}>{t('error.requestFailed')}</Alert>;
  if (!detail) return <CircularProgress size={24} sx={{ mt: 3 }} aria-label={t('scan.loading')} />;
  return (
    <Paper variant="outlined" sx={{ mt: 8, p: { xs: 4, sm: 5 }, overflowWrap: 'anywhere' }} aria-live="polite">
      <Typography variant="h6" component="h2" dir="ltr" sx={{ textAlign: 'start' }}>
        <Box component="span" sx={{ fontFamily: MONO_FONT }}>{detail.technique_id}</Box>
        {detail.technique && ` · ${detail.technique.name}`}
      </Typography>
      {detail.technique && (
        <>
          <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: 'wrap', mt: 1 }}>
            {detail.technique.tactics.map((tactic) => (
              <Chip key={tactic} size="small" label={t(`attack.tactic.${tactic}`, { defaultValue: tactic })} />
            ))}
            {detail.technique.platforms.map((p) => <Chip key={p} size="small" variant="outlined" label={p} />)}
          </Stack>
          {detail.technique.url && (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              {t('attack.reference')}: <InertValue value={detail.technique.url} />
            </Typography>
          )}
        </>
      )}
      <Typography variant="subtitle1" component="h3" sx={{ fontWeight: 600, mt: 2, mb: 1 }}>
        {t('attack.linkedIncidents', { count: detail.incidents.length, findings: detail.findings })}
      </Typography>
      {detail.incidents.length === 0 ? (
        <Typography variant="body2" color="text.secondary">—</Typography>
      ) : (
        <Stack spacing={1}>
          {detail.incidents.map((i) => (
            <Stack key={i.id} direction="row" useFlexGap sx={{ gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
              <Typography variant="body2" dir="ltr" sx={{ fontFamily: MONO_FONT }}>#{i.id}</Typography>
              <SeverityChip severity={i.severity} />
              <StatusChip status={i.status} />
            </Stack>
          ))}
          <Typography variant="caption" color="text.secondary">{t('indicators.openInIncidents')}</Typography>
        </Stack>
      )}
    </Paper>
  );
}
