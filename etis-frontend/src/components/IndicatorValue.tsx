import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Box, IconButton, Tooltip } from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckIcon from '@mui/icons-material/Check';
import { defang, guessIndicatorType, type DefangType } from '../api/defang';
import { InertValue } from './InertValue';

/**
 * An indicator value (URL, domain, IP, e-mail, phone, hash) for people to read: always
 * de-fanged with `defang-v1` (docs/design/core-v2.md §4), inert, never a link, never fetched,
 * and left-to-right inside Arabic layouts. `InertValue` stays for non-indicator text.
 *
 * With `copyable`, a copy button copies the **real** value, and only when it is explicitly
 * clicked (owner instruction for step 9). Nothing is copied on render, hover or selection.
 */
export function IndicatorValue({
  type,
  value,
  muted = false,
  copyable = false,
}: {
  type?: DefangType;
  value: string;
  muted?: boolean;
  copyable?: boolean;
}) {
  const { t } = useTranslation();
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  const shown = defang(type ?? guessIndicatorType(value), value);

  async function copyReal() {
    try {
      await navigator.clipboard.writeText(value);
      setState('copied');
    } catch {
      setState('failed');
    }
    window.setTimeout(() => setState('idle'), 2000);
  }

  return (
    <Box component="span" sx={{ display: 'inline-flex', alignItems: 'center', gap: 1, maxWidth: '100%' }}>
      <InertValue value={shown} muted={muted} />
      {copyable && (
        <Tooltip title={state === 'idle' ? t('indicatorValue.copyReal') : t(`indicatorValue.${state}`)}>
          <IconButton size="small" onClick={copyReal} aria-label={t('indicatorValue.copyReal')}
            sx={{ p: 0.5 }}>
            {state === 'copied' ? <CheckIcon fontSize="inherit" /> : <ContentCopyIcon fontSize="inherit" />}
          </IconButton>
        </Tooltip>
      )}
      {copyable && (
        <Box component="span" role="status" aria-live="polite"
          sx={{ position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0 0 0 0)' }}>
          {state === 'idle' ? '' : t(`indicatorValue.${state}`)}
        </Box>
      )}
    </Box>
  );
}
