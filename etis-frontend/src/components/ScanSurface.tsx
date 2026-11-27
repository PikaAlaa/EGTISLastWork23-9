import type { ReactNode } from 'react';
import { Box, Chip, Stack, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { VerdictKey } from '../theme/tokens';

/**
 * Scan surface (docs/design/console-redesign-v1.md §7).
 * `line`: a shield scan line sweeps over the scanned item (message, URL, file).
 * `radar`: a radar sweep turns in the icon slot (network imports).
 * While scanning the frame is teal; when the result arrives the frame, tint and
 * edge settle into the verdict colour. Content stays inert text.
 */
export type ScanStatus = 'idle' | 'scanning' | VerdictKey;

const CHIP: Record<VerdictKey, 'success' | 'warning' | 'error'> = { LOW: 'success', MEDIUM: 'warning', HIGH: 'error' };

export function ScanSurface({ status, variant = 'line', icon, title, children }: {
  status: ScanStatus; variant?: 'line' | 'radar'; icon: ReactNode; title: ReactNode; children?: ReactNode;
}) {
  const { t } = useTranslation();
  const verdict = status === 'idle' || status === 'scanning' ? null : status;
  return (
    <Box className="etis-scan" data-status={status} aria-busy={status === 'scanning'}>
      <span className="etis-scan__edge" aria-hidden />
      <Stack direction="row" spacing={3} sx={{ p: 4, ps: 5, alignItems: 'flex-start', position: 'relative' }}>
        {variant === 'radar'
          ? <span className="etis-radar" aria-hidden><span className="etis-radar__sweep" />{icon}</span>
          : <Box aria-hidden sx={{ flex: 'none', width: 44, height: 44, borderRadius: 2, display: 'grid', placeItems: 'center',
              bgcolor: 'var(--etis-surface)', color: 'var(--scan-color)', border: 1, borderColor: 'var(--scan-border)',
              transition: 'color 300ms, border-color 300ms' }}>{icon}</Box>}
        <Box sx={{ minWidth: 0, flex: 1 }}>
          <Stack direction="row" spacing={2} sx={{ alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', rowGap: 1 }}>
            <Typography variant="h6" component="div">{title}</Typography>
            <Box role="status" aria-live="polite">
              {status === 'scanning' && <Chip size="small" color="primary" variant="outlined" label={t('designPreview.scan.scanning')} />}
              {verdict && <Chip size="small" color={CHIP[verdict]} label={t(`verdict.${verdict}`)} />}
              {status === 'idle' && <Chip size="small" variant="outlined" label={t('designPreview.scan.ready')} />}
            </Box>
          </Stack>
          {children}
        </Box>
      </Stack>
      {variant === 'line' && <span className="etis-scan__sweep" aria-hidden />}
    </Box>
  );
}
