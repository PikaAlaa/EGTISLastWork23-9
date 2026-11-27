import { Box, Paper, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { BotState } from './botState';

/**
 * ETIS bot: the console's original brand character (docs/design/console-redesign-v1.md §6).
 * A rounded shield with a visor face, one antenna "network node" and a lock on its chest.
 * It is not a chatbot: no input, no generated text. It only mirrors scan state and can
 * show one fixed tip per state from the mascot.tips.* i18n keys.
 */
const BODY = 'M60 18 C76 18 90 23 101 28 Q106 30 106 36 L106 64 C106 94 87 114 60 126 C33 114 14 94 14 64 L14 36 Q14 30 19 28 C30 23 44 18 60 18 Z';

function Face({ state }: { state: BotState }) {
  switch (state) {
    case 'safe':
      return <g className="etis-bot__face">
        <path className="etis-bot__line" d="M42 63 Q48 55 54 63" />
        <path className="etis-bot__line" d="M66 63 Q72 55 78 63" />
        <path className="etis-bot__line" d="M51 71 Q60 79 69 71" />
        <circle className="etis-bot__cheek" cx="37" cy="71" r="4" />
        <circle className="etis-bot__cheek" cx="83" cy="71" r="4" />
      </g>;
    case 'warning':
      return <g className="etis-bot__face">
        <path className="etis-bot__line" d="M41 49 Q48 45 54 48" />
        <path className="etis-bot__line" d="M66 48 Q72 45 79 49" />
        <circle className="etis-bot__eye" cx="48" cy="61" r="6.5" />
        <circle className="etis-bot__eye" cx="72" cy="61" r="6.5" />
        <path className="etis-bot__line" d="M55 75 L65 75" />
      </g>;
    case 'danger':
      return <g className="etis-bot__face">
        <path className="etis-bot__line" d="M41 52 L54 47" />
        <path className="etis-bot__line" d="M66 47 L79 52" />
        <ellipse className="etis-bot__eye" cx="48" cy="62" rx="4" ry="5" />
        <ellipse className="etis-bot__eye" cx="72" cy="62" rx="4" ry="5" />
        <path className="etis-bot__line" d="M52 77 Q60 70 68 77" />
      </g>;
    case 'scanning':
      return <g className="etis-bot__face">
        <g className="etis-bot__look">
          <ellipse className="etis-bot__eye" cx="48" cy="60" rx="4.5" ry="6" />
          <ellipse className="etis-bot__eye" cx="72" cy="60" rx="4.5" ry="6" />
        </g>
        <path className="etis-bot__line" d="M56 74 L64 74" />
      </g>;
    default:
      return <g className="etis-bot__face">
        <g className="etis-bot__blink">
          <ellipse className="etis-bot__eye" cx="48" cy="60" rx="4.5" ry="6" />
          <ellipse className="etis-bot__eye" cx="72" cy="60" rx="4.5" ry="6" />
        </g>
        <path className="etis-bot__line" d="M54 72 Q60 76 66 72" />
      </g>;
  }
}

export function EtisBot({ state = 'idle', size = 112, tip = false, decorative = false }: {
  state?: BotState; size?: number; tip?: boolean; decorative?: boolean;
}) {
  const { t } = useTranslation();
  const label = t(`mascot.state.${state}`);
  return (
    <Box className="etis-bot" data-state={state} sx={{ gap: 1.5 }}>
      <svg width={size} height={size * (140 / 120)} viewBox="0 0 120 140"
        role={decorative ? undefined : 'img'} aria-hidden={decorative || undefined}
        aria-label={decorative ? undefined : label}>
        <ellipse className="etis-bot__shadow" cx="60" cy="134" rx="28" ry="4" />
        <g className="etis-bot__float">
          <line className="etis-bot__stem" x1="60" y1="19" x2="60" y2="9" />
          <circle className="etis-bot__node" cx="60" cy="7" r="5" />
          <path className="etis-bot__body" d={BODY} />
          <ellipse cx="38" cy="36" rx="9" ry="4" fill="#FFFFFF" fillOpacity="0.2" transform="rotate(-18 38 36)" />
          <rect className="etis-bot__visor" x="27" y="40" width="66" height="45" rx="20" />
          <Face key={state} state={state} />
          <path className="etis-bot__shackle" d="M55 101 v-4 a5 5 0 0 1 10 0 v4" />
          <rect className="etis-bot__lock" x="51.5" y="100" width="17" height="12" rx="3" />
        </g>
      </svg>
      {tip && (
        <Paper key={state} variant="outlined" className="etis-bot__tip" role="note"
          sx={{ px: 3, py: 2, maxWidth: 260, borderRadius: 3, bgcolor: 'background.paper' }}>
          <Typography variant="body2" color="text.secondary">{t(`mascot.tips.${state}`)}</Typography>
        </Paper>
      )}
    </Box>
  );
}
