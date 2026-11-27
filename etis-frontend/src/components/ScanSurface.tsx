import type { ReactNode } from 'react';
import { Box, Chip, Stack, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { Verdict } from '../api/types';
import { VerdictChip } from './VerdictChip';

/**
 * Scan surface (docs/design/console-redesign-v1.md §7).
 * `line`: a shield scan line sweeps over the scanned item (message, URL, file).
 * `radar`: a radar sweep turns in the icon slot (network imports).
 * While scanning the frame is teal; when the result arrives the frame, tint and
 * edge settle into the verdict colour. Content stays inert text.
 */
export type ScanStatus = 'idle' | 'scanning' | 'loaded' | Verdict;

export function ScanSurface({ status, variant = 'line', icon, title, statusLabel, children }: {
  status: ScanStatus; variant?: 'line' | 'radar'; icon: ReactNode; title: ReactNode; statusLabel?: string; children?: ReactNode;
}) {
  const { t } = useTranslation();
  const verdict = status === 'idle' || status === 'scanning' || status === 'loaded' ? null : status;
  return (
    <Box className="etis-scan" data-status={status} aria-busy={status === 'scanning'}>
      <span className="etis-scan__edge" aria-hidden />
      <Stack direction="row" spacing={3} sx={{ p: 4, paddingInlineStart: 5, alignItems: 'flex-start', position: 'relative' }}>
        {variant === 'radar'
          ? <span className="etis-radar" aria-hidden><span className="etis-radar__sweep" />{icon}</span>
          : <Box aria-hidden sx={{ flex: 'none', width: 44, height: 44, borderRadius: 2, display: 'grid', placeItems: 'center',
              bgcolor: 'var(--etis-surface)', color: 'var(--scan-color)', border: 1, borderColor: 'var(--scan-border)',
              transition: 'color 300ms, border-color 300ms' }}>{icon}</Box>}
        <Box sx={{ minWidth: 0, flex: 1 }}>
          <Stack direction="row" useFlexGap spacing={2} sx={{ alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', rowGap: 1 }}>
            <Typography variant="h6" component="div">{title}</Typography>
            <Box role="status" aria-live="polite">
              {status === 'scanning' && <Chip size="small" color="primary" variant="outlined" label={t('designPreview.scan.scanning')} />}
              {verdict && <VerdictChip verdict={verdict} label={statusLabel} />}
              {status === 'loaded' && <Chip size="small" variant="outlined" label={statusLabel ?? t('scan.detailLoaded')} />}
              {status === 'idle' && <Chip size="small" variant="outlined" label={t('designPreview.scan.ready')} />}
            </Box>
          </Stack>
        </Box>
      </Stack>
      {children && <Box sx={{ px: 4, pb: 4, minWidth: 0 }}>{children}</Box>}
      {variant === 'line' && <span className="etis-scan__sweep" aria-hidden />}
    </Box>
  );
}
