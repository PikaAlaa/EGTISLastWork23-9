import type { ReactNode } from 'react';
import { Paper, Stack, Typography, Chip, Box } from '@mui/material';
import { useTranslation } from 'react-i18next';

import type { Verdict } from '../api/types';
import { VERDICT_STYLE } from '../theme/verdictPalette';

interface EngineBreakdownCardProps {
  icon: ReactNode;
  verdict?: Verdict;
  title: string;
  /** Null when the engine didn't run for this input (e.g. blacklist on a text-only submission). */
  applicable: boolean;
  /**
   * Localized reason the engine didn't run, e.g. "No URL was submitted."
   * Shown instead of the generic "not applicable" line when provided.
   * Ignored when `applicable` is true. Callers derive this from the
   * API's `skip_reasons` field (see risk_scoring.py) via
   * scan.skipReasonNoUrl / scan.skipReasonNoText.
   */
  notApplicableReason?: string;
  /** Engine's own 0-100 internal score -- NOT the same scale as `contribution` (see note below). */
  score?: number;
  /** This engine's actual weighted contribution to the final 0-100 score, already scale-adjusted. */
  contribution?: number;
  /**
   * Wall-clock time this engine took, in milliseconds (see
   * risk_scoring.py's stage_timings field). Shown as a chip alongside
   * score/contribution when provided -- for presentation/explainability
   * (e.g. showing LSTM inference dominates latency), not a performance
   * diagnostic tool. Omitted (undefined/null) when not applicable, since
   * the engine didn't run.
   */
  timingMs?: number | null;
  children?: ReactNode;
}

/**
 * Deliberately does NOT show contribution as "x/30" or similar -- the
 * per-engine max points (30/40/30) get proportionally redistributed when
 * an engine doesn't apply (see risk_scoring.py's scale_factor), so a
 * fixed denominator would misrepresent what the number means. `score` and
 * `contribution` are shown as two separate, honestly-labeled numbers
 * instead of implying a fraction that isn't actually fixed.
 */
export function EngineBreakdownCard({
  icon,
  title,
  applicable,
  verdict,
  notApplicableReason,
  score,
  contribution,
  timingMs,
  children,
}: EngineBreakdownCardProps) {
  const { t } = useTranslation();

  const tone = verdict && VERDICT_STYLE[verdict];
  return (
    <Paper
      variant="outlined"
      className="etis-result"
      sx={{
        '--scan-color': tone?.accent ?? 'var(--etis-accent)',
        p: 4,
        bgcolor: tone?.bg ?? 'background.paper',
        borderColor: tone?.border ?? 'divider',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      <Stack direction="row" spacing={3} sx={{ alignItems: 'center', mb: 1 }}>
        <Box sx={{ display: 'grid', placeItems: 'center', p: 2, bgcolor: 'background.paper', borderRadius: 1, color: tone?.accent ?? 'primary.main' }}>{icon}</Box>
        <Typography variant="subtitle2" sx={{ fontWeight: 600, flexGrow: 1 }}>
          {title}
        </Typography>
      </Stack>

      {applicable ? (
        <>
          <Stack direction="row" useFlexGap spacing={2} sx={{ mt: 2, mb: 2, flexWrap: 'wrap' }}>
            {score !== undefined && (
              <Chip size="small" variant="outlined" label={<>{t('scan.score')} · <bdi dir="ltr">{score}/100</bdi></>} />
            )}
            {contribution !== undefined && (
              <Chip size="small" variant="outlined" label={<>{t('scan.contribution')} · <bdi dir="ltr">+{contribution}</bdi></>} />
            )}
            {timingMs !== undefined && timingMs !== null && (
              <Chip size="small" variant="outlined" label={<>{t('scan.timingLabel')} · {t('scan.engineTime', { value: timingMs })}</>} />
            )}
          </Stack>
          <Box sx={{ flexGrow: 1 }}>{children}</Box>
        </>
      ) : (
        <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic' }}>
          {notApplicableReason ?? t('scan.notApplicable')}
        </Typography>
      )}
    </Paper>
  );
}
