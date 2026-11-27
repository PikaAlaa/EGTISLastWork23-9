import type { ReactNode } from 'react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Box, Button, Typography, CircularProgress, Alert, Grid, Paper, Stack } from '@mui/material';
import StorageOutlined from '@mui/icons-material/StorageOutlined';
import CheckCircleOutlineOutlined from '@mui/icons-material/CheckCircleOutlineOutlined';
import FactCheckOutlined from '@mui/icons-material/FactCheckOutlined';
import SpeedOutlined from '@mui/icons-material/SpeedOutlined';

import { getStats, ApiError } from '../api/client';
import type { StatsResponse, Verdict } from '../api/types';
import { VerdictChip } from '../components/VerdictChip';

export function StatsPage() {
  const { t } = useTranslation();
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [retry, setRetry] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      setStats(null);
      setError(null);
      try {
        const response = await getStats();
        if (!cancelled) setStats(response);
      } catch (err) {
        if (cancelled) return;
        if (err instanceof ApiError) {
          setError('requestFailed');
        } else {
          setError('requestFailed');
          console.error('Request failed');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, [retry]);

  return (
    <Box>
      <Typography variant="h1" component="h1" gutterBottom>
        {t('nav.stats')}
      </Typography>

      {loading && <CircularProgress size={24} aria-label={t('scan.loading')} />}
      {error && <Alert severity="error" action={<Button color="inherit" onClick={() => setRetry(r => r + 1)}>{t('common.retry')}</Button>}>{t(`error.${error}`)}</Alert>}

      {stats && (
        <Grid container spacing={4} sx={{ mt: 4 }}>
          <Grid size={{ xs: 6, sm: 3 }}>
            <StatCard
              icon={<StorageOutlined fontSize="small" />}
              label={t('stats.totalEntries')}
              value={stats.blacklist.total_entries.toLocaleString()}
            />
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <StatCard
              icon={<CheckCircleOutlineOutlined fontSize="small" />}
              label={t('stats.activeEntries')}
              value={stats.blacklist.active_entries.toLocaleString()}
            />
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <StatCard
              icon={<FactCheckOutlined fontSize="small" />}
              label={t('stats.totalScans')}
              value={stats.scans.total_scans.toLocaleString()}
            />
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <StatCard
              icon={<SpeedOutlined fontSize="small" />}
              label={t('stats.averageScore')}
              value={stats.scans.average_final_score !== null ? stats.scans.average_final_score.toFixed(2) : '—'}
            />
          </Grid>

          <Grid size={{ xs: 12, sm: 6 }}>
            <Paper variant="outlined" sx={{ p: 5, height: '100%' }}>
              <Typography variant="h4" component="h2" gutterBottom>
                {t('stats.bySourceHeading')}
              </Typography>
              <Stack spacing={3} sx={{ mt: 4 }}>
                {Object.entries(stats.blacklist.by_source).map(([source, count]) => (
                  <Stack key={source} direction="row" sx={{ justifyContent: 'space-between' }}>
                    <Typography variant="body2">{t(`source.${source}`)}</Typography>
                    <Typography variant="body2" dir="ltr" sx={{ fontWeight: 600, fontFamily: "'IBM Plex Mono', monospace" }}>
                      {count.toLocaleString()}
                    </Typography>
                  </Stack>
                ))}
              </Stack>
            </Paper>
          </Grid>

          <Grid size={{ xs: 12, sm: 6 }}>
            <Paper variant="outlined" sx={{ p: 5, height: '100%' }}>
              <Typography variant="h4" component="h2" gutterBottom>
                {t('stats.byVerdictHeading')}
              </Typography>
              <Stack spacing={3} sx={{ mt: 4 }}>
                {(Object.entries(stats.scans.by_verdict) as [Verdict, number][]).map(([verdict, count]) => (
                  <Stack key={verdict} direction="row" spacing={2} sx={{ alignItems: 'center', justifyContent: 'space-between' }}>
                    <VerdictChip verdict={verdict} />
                    <Typography variant="body2" dir="ltr" sx={{ fontWeight: 600, fontFamily: "'IBM Plex Mono', monospace" }}>
                      {count.toLocaleString()}
                    </Typography>
                  </Stack>
                ))}
              </Stack>
            </Paper>
          </Grid>
        </Grid>
      )}
    </Box>
  );
}

function StatCard({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <Paper variant="outlined" className="etis-lift" sx={{ p: { xs: 4, sm: 5 }, height: '100%' }}>
      <Stack direction="row" sx={{ justifyContent: 'space-between', gap: 2, alignItems: 'center' }}>
        <Typography variant="body2" color="text.secondary">{label}</Typography>
        <Box sx={{ display: 'flex', color: 'primary.main' }}>{icon}</Box>
      </Stack>
      <Typography variant="h2" component="div" dir="ltr"
        sx={{ mt: 2, fontFamily: "'IBM Plex Mono', monospace", fontWeight: 600, overflowWrap: 'anywhere' }}>
        {value}
      </Typography>
    </Paper>
  );
}
