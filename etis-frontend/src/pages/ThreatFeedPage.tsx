import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Typography,
  CircularProgress,
  Alert,
  Table,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  Chip,
  Stack,
  Button,
  TextField,
  MenuItem,
  Paper,
} from '@mui/material';

import { getThreats, ApiError } from '../api/client';
import { IndicatorValue } from '../components/IndicatorValue';
import type { ThreatEntry } from '../api/types';

const PAGE_SIZE = 20;
const MONO_FONT = "'IBM Plex Mono', monospace";

export function ThreatFeedPage() {
  const { t } = useTranslation();
  const [entries, setEntries] = useState<ThreatEntry[]>([]);
  const [totalMatching, setTotalMatching] = useState(0);
  const [offset, setOffset] = useState(0);
  const [source, setSource] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [retry, setRetry] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const response = await getThreats({
          limit: PAGE_SIZE,
          offset,
          source: source || undefined,
        });
        if (!cancelled) {
          setEntries(response.results);
          setTotalMatching(response.total_matching);
        }
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
  }, [offset, source, retry]);

  const canGoPrev = offset > 0;
  const canGoNext = offset + PAGE_SIZE < totalMatching;
  const rangeStart = totalMatching === 0 ? 0 : offset + 1;
  const rangeEnd = Math.min(offset + PAGE_SIZE, totalMatching);

  return (
    <Box>
      <Typography variant="h1" component="h1" gutterBottom>
        {t('nav.threats')}
      </Typography>

      <Paper variant="outlined" className="etis-filters">
        <TextField
          select
          label={t('threats.source')}
          size="small"
          slotProps={{ select: { displayEmpty: true }, inputLabel: { shrink: true } }}
          value={source}
          onChange={(e) => {
            setOffset(0);
            setSource(e.target.value);
          }}
          sx={{ minWidth: 160 }}
        >
          <MenuItem value="">{t('threats.allSources')}</MenuItem>
          <MenuItem value="phishtank">phishtank</MenuItem>
          <MenuItem value="openphish">openphish</MenuItem>
          <MenuItem value="manual">{t('source.manual')}</MenuItem>
        </TextField>

        <Typography variant="body2" color="text.secondary">
          <Box component="span" sx={{ fontFamily: MONO_FONT }}>
            {totalMatching.toLocaleString()}
          </Box>{' '}
          {t('threats.totalMatching')}
        </Typography>
      </Paper>

      {loading && <CircularProgress size={24} aria-label={t('scan.loading')} />}
      {error && <Alert severity="error" action={<Button color="inherit" onClick={() => setRetry(r => r + 1)}>{t('common.retry')}</Button>}>{t(`error.${error}`)}</Alert>}

      {!loading && !error && entries.length === 0 && (
        <Paper variant="outlined" sx={{ p: 6, textAlign: 'center' }}>
          <Typography variant="body2" color="text.secondary">
            {t('threats.noResults')}
          </Typography>
        </Paper>
      )}

      {!loading && !error && entries.length > 0 && (
        <>
          <Paper variant="outlined" sx={{ overflowX: 'auto' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 600 }}>{t('threats.domain')}</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{t('threats.source')}</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{t('threats.brandTarget')}</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{t('threats.reputationScore')}</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{t('threats.lastSeen')}</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{t('threats.active')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {entries.map((entry) => (
                  <TableRow key={entry.id} hover>
                    <TableCell><IndicatorValue type="domain" value={entry.domain} /></TableCell>
                    <TableCell>{entry.source}</TableCell>
                    <TableCell>{entry.brand_target ?? '—'}</TableCell>
                    <TableCell dir="ltr" sx={{ fontFamily: MONO_FONT, fontSize: '0.8rem' }}>{entry.reputation_score}</TableCell>
                    <TableCell dir="ltr" sx={{ fontFamily: MONO_FONT, fontSize: '0.8rem' }}>{entry.last_seen}</TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        label={entry.is_active ? t('threats.active') : t('threats.inactive')}
                        color={entry.is_active ? 'primary' : 'default'}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Paper>

          <Stack direction="row" useFlexGap spacing={3} sx={{ mt: 4, flexWrap: 'wrap', alignItems: 'center' }}>
            <Button size="small" disabled={!canGoPrev} onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}>
              {t('threats.previous')}
            </Button>
            <Button size="small" disabled={!canGoNext} onClick={() => setOffset((o) => o + PAGE_SIZE)}>
              {t('threats.next')}
            </Button>
            <Typography
              variant="caption"
              color="text.secondary"
              component="span"
              dir="ltr"
              sx={{ display: 'inline-block', fontFamily: MONO_FONT }}
            >
              {rangeStart.toLocaleString()}–{rangeEnd.toLocaleString()} / {totalMatching.toLocaleString()}
            </Typography>
          </Stack>
        </>
      )}
    </Box>
  );
}
