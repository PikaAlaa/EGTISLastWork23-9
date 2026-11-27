import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Box, Button, Chip, Paper, Stack, TextField, Typography } from '@mui/material';
import { InertValue } from './InertValue';

const EXT_ID_RE = /^[a-p]{32}$/;

interface PairingStatus {
  paired: boolean;
  revoked: boolean;
  approved_origin: string | null;
  server_instance_id: string;
}

export function ExtensionPairingPanel() {
  const { t } = useTranslation();
  const [extensionId, setExtensionId] = useState('');
  const [status, setStatus] = useState<PairingStatus | null>(null);
  const [oneUseSecret, setOneUseSecret] = useState<string | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function loadStatus() {
    try {
      const res = await fetch('/api/extension/v1/status', { headers: { Accept: 'application/json' } });
      if (res.ok) {
        setStatus((await res.json()) as PairingStatus);
      }
    } catch {
      // Status is optional when backend is unreachable.
    }
  }

  useEffect(() => {
    void loadStatus();
    return () => {
      setOneUseSecret(null);
    };
  }, []);

  const trimmedId = extensionId.trim();
  const idValid = EXT_ID_RE.test(trimmedId);

  async function handleGenerateSecret(e: React.FormEvent) {
    e.preventDefault();
    setErrorCode(null);
    setOneUseSecret(null);
    if (!idValid) {
      setErrorCode('invalidExtensionId');
      return;
    }
    setBusy(true);
    try {
      const res = await fetch('/api/extension/v1/pairing-secret', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ extension_id: trimmedId }),
      });
      if (!res.ok) {
        setErrorCode('pairingFailed');
        return;
      }
      const data = (await res.json()) as { pairing_secret?: string };
      setOneUseSecret(data.pairing_secret ?? null);
      await loadStatus();
    } catch {
      setErrorCode('pairingFailed');
    } finally {
      setBusy(false);
    }
  }

  async function handleRevoke() {
    setErrorCode(null);
    setOneUseSecret(null);
    setBusy(true);
    try {
      const res = await fetch('/api/extension/v1/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      });
      if (res.ok) {
        await loadStatus();
      } else {
        setErrorCode('pairingFailed');
      }
    } catch {
      setErrorCode('pairingFailed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Paper variant="outlined" sx={{ p: 2.5, mt: 4, maxWidth: 650 }}>
      <Stack spacing={1.5}>
        <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 1 }}>
          <Typography variant="h6" component="h2">
            {t('extensionPairing.title')}
          </Typography>
          {status && (
            <Chip
              size="small"
              color={status.paired ? 'success' : status.revoked ? 'warning' : 'default'}
              label={
                status.paired
                  ? t('extensionPairing.statusPaired')
                  : status.revoked
                    ? t('extensionPairing.statusRevoked')
                    : t('extensionPairing.statusUnpaired')
              }
            />
          )}
        </Stack>
        <Typography variant="body2" color="text.secondary">
          {t('extensionPairing.description')}
        </Typography>
        <Box component="form" onSubmit={handleGenerateSecret}>
          <Stack spacing={1.5}>
            <TextField
              size="small"
              label={t('extensionPairing.extensionIdLabel')}
              value={extensionId}
              disabled={busy}
              onChange={(e) => {
                setExtensionId(e.target.value);
                setErrorCode(null);
              }}
              error={Boolean(trimmedId && !idValid)}
              helperText={t('extensionPairing.extensionIdHelp')}
              slotProps={{ htmlInput: { maxLength: 32, dir: 'ltr', spellCheck: false } }}
              placeholder="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              fullWidth
            />
            <Stack direction="row" spacing={1}>
              <Button type="submit" variant="outlined" disabled={busy || !idValid}>
                {t('extensionPairing.generateSecret')}
              </Button>
              <Button type="button" color="warning" variant="text" disabled={busy} onClick={() => void handleRevoke()}>
                {t('extensionPairing.revoke')}
              </Button>
            </Stack>
          </Stack>
        </Box>
        {errorCode && <Alert severity="error">{t(`extensionPairing.${errorCode}`)}</Alert>}
        {oneUseSecret && (
          <Alert severity="info" onClose={() => setOneUseSecret(null)}>
            <Typography variant="body2" sx={{ mb: 0.5 }}>
              {t('extensionPairing.secretIssuedNote')}
            </Typography>
            <InertValue value={oneUseSecret} />
          </Alert>
        )}
      </Stack>
    </Paper>
  );
}
