import type { VerdictKey } from '../theme/tokens';

/** ETIS bot states (docs/design/console-redesign-v1.md §6). */
export type BotState = 'idle' | 'scanning' | 'safe' | 'warning' | 'danger';

export const BOT_STATES: BotState[] = ['idle', 'scanning', 'safe', 'warning', 'danger'];

export function botStateFor(status: 'idle' | 'scanning' | VerdictKey): BotState {
  if (status === 'LOW') return 'safe';
  if (status === 'MEDIUM') return 'warning';
  if (status === 'HIGH') return 'danger';
  return status;
}
