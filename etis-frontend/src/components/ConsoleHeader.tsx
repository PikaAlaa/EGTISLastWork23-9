import { AppBar, Box, Button, IconButton, Stack, Tab, Tabs, Toolbar, Tooltip, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import { NAV, type PageKey } from '../navigation';
import DarkModeOutlinedIcon from '@mui/icons-material/DarkModeOutlined';
import LightModeOutlinedIcon from '@mui/icons-material/LightModeOutlined';
import TranslateIcon from '@mui/icons-material/Translate';
import { TOKENS, type ColorMode } from '../theme/tokens';
import { EtisBot } from './EtisBot';

interface HeaderProps {
  mode: ColorMode;
  page: PageKey;
  onNavigate: (page: PageKey) => void;
  onToggleMode: () => void;
}

export function ConsoleHeader({ mode, page, onNavigate, onToggleMode }: HeaderProps) {
  const { t, i18n } = useTranslation();
  const isRtl = i18n.language === 'ar';
  return (
    <AppBar position="static" sx={{ bgcolor: TOKENS[mode].navy, color: TOKENS[mode].onNavy }}>
      <Toolbar sx={{ gap: 2, flexWrap: 'wrap', py: 2 }}>
        <Stack direction="row" spacing={2} sx={{ alignItems: 'center', flexGrow: 1, minWidth: 0 }}>
          <EtisBot size={30} decorative />
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="h6" component="div" sx={{ lineHeight: 1.2 }}>{t('app.title')}</Typography>
            <Typography variant="caption" sx={{ opacity: 0.8, display: { xs: 'none', sm: 'block' } }}>{t('app.subtitle')}</Typography>
          </Box>
        </Stack>
        <Tooltip title={t(mode === 'light' ? 'app.darkTheme' : 'app.lightTheme')}>
          <IconButton color="inherit" onClick={onToggleMode}
            aria-label={t(mode === 'light' ? 'app.darkTheme' : 'app.lightTheme')}>
            {mode === 'light' ? <DarkModeOutlinedIcon /> : <LightModeOutlinedIcon />}
          </IconButton>
        </Tooltip>
        <Button color="inherit" startIcon={<TranslateIcon />} onClick={() => i18n.changeLanguage(isRtl ? 'en' : 'ar')}>
          {t('app.switchLanguage')}
        </Button>
      </Toolbar>
      <Tabs value={page} onChange={(_, value: PageKey) => onNavigate(value)} variant="scrollable" scrollButtons="auto" allowScrollButtonsMobile
        aria-label={t('common.navigation')} textColor="inherit"
        sx={{ px: 2, '& .MuiTabs-indicator': { bgcolor: TOKENS[mode].accentOnNavy, height: 3, borderRadius: 3 } }}>
        {NAV.map(([key, Icon]) => <Tab key={key} value={key} icon={<Icon />} iconPosition="start" label={t(`nav.${key}`)} />)}
      </Tabs>
    </AppBar>
  );
}
