import { Box, Chip } from '@mui/material';
import CircleOutlinedIcon from '@mui/icons-material/CircleOutlined';
import PendingOutlinedIcon from '@mui/icons-material/PendingOutlined';
import TaskAltOutlinedIcon from '@mui/icons-material/TaskAltOutlined';
import { useTranslation } from 'react-i18next';
import type { IncidentStatus, Severity } from '../api/socTypes';

const SEVERITY_COLOR: Record<Severity, 'default' | 'info' | 'warning' | 'error'> = {
  info: 'default',
  low: 'info',
  medium: 'warning',
  high: 'error',
  critical: 'error',
};

const STATUS_ICON = { open: CircleOutlinedIcon, investigating: PendingOutlinedIcon, resolved: TaskAltOutlinedIcon };

export function SeverityChip({ severity }: { severity: Severity }) {
  const { t } = useTranslation();
  return (
    <Chip
      size="small"
      color={SEVERITY_COLOR[severity]}
      sx={{ fontWeight: 700 }}
      variant={severity === 'critical' ? 'filled' : 'outlined'}
      label={t(`soc.severity.${severity}`)}
    />
  );
}

export function StatusChip({ status }: { status: IncidentStatus }) {
  const { t } = useTranslation();
  const Icon = STATUS_ICON[status];
  return <Chip size="small" icon={<Icon />} label={t(`soc.status.${status}`)}
    sx={{ bgcolor: 'var(--etis-surface2)', color: 'text.secondary', '& .MuiChip-icon': { color: 'inherit' } }} />;
}

/** ISO timestamp as a compact, left-to-right "YYYY-MM-DD HH:MM" (stored as UTC). */
export function Timestamp({ value }: { value: string | null }) {
  if (!value) return <>—</>;
  const text = value.replace('T', ' ').slice(0, 16);
  return (
    <Box component="span" dir="ltr" sx={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: '0.8rem', whiteSpace: 'nowrap', unicodeBidi: 'isolate' }}>
      {text}
    </Box>
  );
}
