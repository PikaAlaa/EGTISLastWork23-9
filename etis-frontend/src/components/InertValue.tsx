import { Box } from '@mui/material';

/**
 * Displays an indicator (URL, domain, IP, phone, email, hash) as inert text:
 * never a link, never fetched, left-to-right even inside Arabic layouts.
 */
export function InertValue({ value, muted = false }: { value: string; muted?: boolean }) {
  return (
    <Box
      component="span"
      dir="ltr"
      translate="no"
      sx={{
        fontFamily: "'IBM Plex Mono', monospace",
        fontSize: '0.8rem',
        overflowWrap: 'anywhere',
        color: muted ? 'text.secondary' : 'text.primary',
      }}
    >
      {value}
    </Box>
  );
}
