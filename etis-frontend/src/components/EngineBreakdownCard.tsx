import type { ReactNode } from 'react';
import { Paper, Stack, Typography, Chip, Box } from '@mui/material';
import { useTranslation } from 'react-i18next';

interface EngineBreakdownCardProps {
  icon: ReactNode;
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
  notApplicableReason,
  score,
  contribution,
  timingMs,
  children,
}: EngineBreakdownCardProps) {
  const { t } = useTranslation();

  return (
    <Paper
      variant="outlined"
      sx={{
        p: 2,
        borderRadius: 3,
        height: '100%',
        opacity: applicable ? 1 : 0.55,
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      <Stack direction="row" spacing={1} sx={{ alignItems: 'center', mb: 1 }}>
        {icon}
        <Typography variant="subtitle2" sx={{ fontWeight: 600, flexGrow: 1 }}>
          {title}
        </Typography>
      </Stack>

      {applicable ? (
        <>
          <Stack direction="row" spacing={1} sx={{ mb: 1.5, flexWrap: 'wrap' }}>
            {score !== undefined && (
              <Chip size="small" variant="outlined" label={`${t('scan.score')}: ${score}/100`} />
            )}
            {contribution !== undefined && (
              <Chip size="small" variant="outlined" label={`${t('scan.contribution')}: +${contribution}`} />
            )}
            {timingMs !== undefined && timingMs !== null && (
              <Chip size="small" variant="outlined" label={`${t('scan.timingLabel')}: ${timingMs}ms`} />
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
