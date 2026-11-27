import type { Verdict } from '../api/types';

interface VerdictStyle {
  bg: string;
  accent: string;
  border: string;
}

export const VERDICT_STYLE: Record<Verdict, VerdictStyle> = {
  LOW: { bg: 'var(--etis-low-tint)', accent: 'var(--etis-low-text)', border: 'var(--etis-low-border)' },
  MEDIUM: { bg: 'var(--etis-medium-tint)', accent: 'var(--etis-medium-text)', border: 'var(--etis-medium-border)' },
  HIGH: { bg: 'var(--etis-high-tint)', accent: 'var(--etis-high-text)', border: 'var(--etis-high-border)' },
  INCOMPLETE: { bg: 'var(--etis-surface2)', accent: 'var(--etis-incomplete)', border: 'var(--etis-border)' },
};
