import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Box, Button, Chip, Stack, Typography } from '@mui/material';
import TipsAndUpdatesOutlinedIcon from '@mui/icons-material/TipsAndUpdatesOutlined';
import type { RecommendedAction } from '../api/socTypes';

/**
 * Recommended actions (design core-v2 §2.3-§2.5, FR-14). Fixed, reviewed text for a person to
 * read: no button here does anything but switch the language. ETIS never acts on the system.
 *
 * The backend returns draft texts only when ETIS_SHOW_DRAFT_ACTIONS is set; this component
 * renders **nothing** for an empty list (no placeholder, no "draft" notice), and marks a draft
 * text "Draft, not reviewed" only when the backend sent one.
 */
export function RecommendedActions({ actions, compact = false }: { actions?: RecommendedAction[]; compact?: boolean }) {
  const { t, i18n } = useTranslation();
  const appLang = i18n.language === 'ar' ? 'ar' : 'en';
  const [other, setOther] = useState(false);
  if (!actions || actions.length === 0) return null;
  const lang: 'ar' | 'en' = other ? (appLang === 'ar' ? 'en' : 'ar') : appLang;
  const shown = compact ? actions.slice(0, 1) : actions;

  return (
    <Box role="note" aria-label={t('actions.heading')}>
      <Stack spacing={compact ? 1 : 2}>
        {shown.map((action, index) => (
          <Stack key={`${action.reason_code ?? action.source}-${index}`} direction="row" spacing={2}
            sx={{ alignItems: 'flex-start' }}>
            {!compact && <TipsAndUpdatesOutlinedIcon fontSize="small" color="primary" aria-hidden sx={{ mt: 0.5 }} />}
            <Box sx={{ minWidth: 0 }}>
              <Typography variant={compact ? 'body2' : 'body1'} lang={lang} dir={lang === 'ar' ? 'rtl' : 'ltr'}
                sx={{ fontWeight: !compact && index === 0 ? 600 : undefined }}>
                {action[lang]}
              </Typography>
              {!compact && (
                <Stack direction="row" useFlexGap sx={{ gap: 1, mt: 1, flexWrap: 'wrap' }}>
                  {index === 0 && <Chip size="small" color="primary" variant="outlined" label={t('actions.primary')} />}
                  <Chip size="small" variant="outlined" label={t(`actions.audience.${action.audience}`)} />
                  {action.status === 'draft' && <Chip size="small" variant="outlined" label={t('actions.draft')} />}
                </Stack>
              )}
              {compact && action.status === 'draft' && (
                <Typography variant="caption" color="text.secondary">{t('actions.draft')}</Typography>
              )}
            </Box>
          </Stack>
        ))}
      </Stack>
      <Stack direction="row" useFlexGap sx={{ gap: 2, mt: compact ? 0.5 : 2, flexWrap: 'wrap', alignItems: 'center' }}>
        <Button size="small" onClick={() => setOther((value) => !value)} sx={{ px: 1 }}>
          {lang === 'ar' ? t('actions.showEnglish') : t('actions.showArabic')}
        </Button>
        {!compact && (
          <Typography variant="caption" color="text.secondary">
            {t('actions.notice', { version: actions[0].catalogue_version })}
          </Typography>
        )}
      </Stack>
    </Box>
  );
}
