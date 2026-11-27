import type { Verdict } from '../api/types';

interface VerdictStyle {
  bg: string;
  accent: string;
  border: string;
  chipColor: 'success' | 'warning' | 'error' | 'default';
}

export const VERDICT_STYLE: Record<Verdict, VerdictStyle> = {
  LOW: { bg: 'var(--etis-low-tint)', accent: 'var(--etis-low-text)', border: 'var(--etis-low-border)', chipColor: 'success' },
  MEDIUM: { bg: 'var(--etis-medium-tint)', accent: 'var(--etis-medium-text)', border: 'var(--etis-medium-border)', chipColor: 'warning' },
  HIGH: { bg: 'var(--etis-high-tint)', accent: 'var(--etis-high-text)', border: 'var(--etis-high-border)', chipColor: 'error' },
  INCOMPLETE: { bg: 'var(--etis-surface2)', accent: 'var(--etis-incomplete)', border: 'var(--etis-border)', chipColor: 'default' },
};
