import { Chip } from '@mui/material';
import GppGoodOutlinedIcon from '@mui/icons-material/GppGoodOutlined';
import GppMaybeOutlinedIcon from '@mui/icons-material/GppMaybeOutlined';
import GppBadOutlinedIcon from '@mui/icons-material/GppBadOutlined';
import ShieldOutlinedIcon from '@mui/icons-material/ShieldOutlined';
import { useTranslation } from 'react-i18next';
import type { Verdict } from '../api/types';
import { VERDICT_STYLE } from '../theme/verdictPalette';

const ICON = { LOW: GppGoodOutlinedIcon, MEDIUM: GppMaybeOutlinedIcon, HIGH: GppBadOutlinedIcon, INCOMPLETE: ShieldOutlinedIcon };

export function VerdictChip({ verdict, label }: { verdict: Verdict; label?: string }) {
  const { t } = useTranslation();
  const Icon = ICON[verdict];
  const style = VERDICT_STYLE[verdict];
  return <Chip size="small" icon={<Icon />} label={label ?? t(`verdict.${verdict}`)}
    sx={{ bgcolor: style.bg, color: style.accent, border: 1, borderColor: style.border,
      '& .MuiChip-icon': { color: 'inherit' } }} />;
}
