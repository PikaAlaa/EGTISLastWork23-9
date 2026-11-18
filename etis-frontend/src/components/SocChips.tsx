import { Box, Chip } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { IncidentStatus, Severity } from '../api/socTypes';

const SEVERITY_COLOR: Record<Severity, 'default' | 'info' | 'warning' | 'error'> = {
  info: 'default',
  low: 'info',
  medium: 'warning',
  high: 'error',
  critical: 'error',
};

const STATUS_COLOR: Record<IncidentStatus, 'warning' | 'info' | 'success'> = {
  open: 'warning',
  investigating: 'info',
  resolved: 'success',
};

export function SeverityChip({ severity }: { severity: Severity }) {
  const { t } = useTranslation();
  return (
    <Chip
      size="small"
      color={SEVERITY_COLOR[severity]}
      variant={severity === 'critical' ? 'filled' : 'outlined'}
      label={t(`soc.severity.${severity}`)}
    />
  );
}

export function StatusChip({ status }: { status: IncidentStatus }) {
  const { t } = useTranslation();
  return <Chip size="small" color={STATUS_COLOR[status]} label={t(`soc.status.${status}`)} />;
}

/** ISO timestamp as a compact, left-to-right "YYYY-MM-DD HH:MM" (stored as UTC). */
export function Timestamp({ value }: { value: string | null }) {
  if (!value) return <>—</>;
  const text = value.replace('T', ' ').slice(0, 16);
  return (
    <Box component="span" dir="ltr" sx={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: '0.8rem' }}>
      {text}
    </Box>
  );
}
