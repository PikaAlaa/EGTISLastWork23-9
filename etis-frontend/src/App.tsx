import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CacheProvider } from '@emotion/react';
import {
  ThemeProvider,
  CssBaseline,
  AppBar,
  Toolbar,
  Typography,
  Tabs,
  Tab,
  Container,
  Button,
  Box,
} from '@mui/material';

import { createEtisTheme } from './theme/theme';
import { createRtlCache, createLtrCache } from './theme/rtlCache';
import { ScanPage } from './pages/ScanPage';
import { ThreatFeedPage } from './pages/ThreatFeedPage';
import { StatsPage } from './pages/StatsPage';

const PAGES = ['scan', 'threats', 'stats'] as const;
type PageKey = (typeof PAGES)[number];

export default function App() {
  const { t, i18n } = useTranslation();
  const [activePage, setActivePage] = useState<PageKey>(() => PAGES.includes(location.pathname.slice(1) as PageKey) ? location.pathname.slice(1) as PageKey : 'scan');

  useEffect(() => {
    const update = () => setActivePage(PAGES.includes(location.pathname.slice(1) as PageKey) ? location.pathname.slice(1) as PageKey : 'scan');
    window.addEventListener('popstate', update);
    return () => window.removeEventListener('popstate', update);
  }, []);

  const isRtl = i18n.language === 'ar';
  const direction = isRtl ? 'rtl' : 'ltr';

  // Theme and emotion cache both depend on direction, so both are
  // recreated together when the language toggle flips it.
  const theme = useMemo(() => createEtisTheme(direction), [direction]);
  const cache = useMemo(() => (isRtl ? createRtlCache() : createLtrCache()), [isRtl]);

  useEffect(() => {
    document.documentElement.dir = direction;
    document.documentElement.lang = i18n.language;
  }, [direction, i18n.language]);

  function toggleLanguage() {
    i18n.changeLanguage(isRtl ? 'en' : 'ar');
  }

  return (
    <CacheProvider value={cache}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <AppBar position="static" color="primary">
          <Toolbar sx={{ gap: 2 }}>
            <Typography variant="h6" sx={{ flexGrow: 1 }}>
              {t('app.title')}
            </Typography>
            <Button color="inherit" onClick={toggleLanguage}>
              {isRtl ? 'English' : 'العربية'}
            </Button>
          </Toolbar>
        </AppBar>

        <Container maxWidth="lg" component="main">
          <Tabs aria-label={t('common.navigation')}
            value={activePage}
            onChange={(_, value: PageKey) => { history.pushState(null, '', '/' + value); setActivePage(value); }}
            sx={{ borderBottom: 1, borderColor: 'divider', mt: 1 }}
          >
            <Tab value="scan" label={t('nav.scan')} />
            <Tab value="threats" label={t('nav.threats')} />
            <Tab value="stats" label={t('nav.stats')} />
          </Tabs>

          <Box>
            {activePage === 'scan' && <ScanPage />}
            {activePage === 'threats' && <ThreatFeedPage />}
            {activePage === 'stats' && <StatsPage />}
          </Box>
        </Container>
      </ThemeProvider>
    </CacheProvider>
  );
}
