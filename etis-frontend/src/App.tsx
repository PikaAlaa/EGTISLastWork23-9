import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CacheProvider } from '@emotion/react';
import { ThemeProvider, CssBaseline, Container, useMediaQuery } from '@mui/material';
import { ConsoleHeader } from './components/ConsoleHeader';
import { pageFromPath, type PageKey } from './navigation';
import { createConsoleTheme } from './theme/consoleTheme';
import type { ColorMode } from './theme/tokens';
import { createRtlCache, createLtrCache } from './theme/rtlCache';
import { ScanPage } from './pages/ScanPage';
import { ThreatFeedPage } from './pages/ThreatFeedPage';
import { StatsPage } from './pages/StatsPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { IndicatorsPage } from './pages/IndicatorsPage';
import { AttackPage } from './pages/AttackPage';
import { FileScansPage } from './pages/FileScansPage';
import { NetworkWindowsPage } from './pages/NetworkWindowsPage';

const THEME_KEY = 'etis-console-theme';

function storedMode(): ColorMode | null {
  try {
    const mode = localStorage.getItem(THEME_KEY);
    return mode === 'light' || mode === 'dark' ? mode : null;
  } catch {
    return null;
  }
}

export default function App() {
  const { i18n } = useTranslation();
  const [activePage, setActivePage] = useState(pageFromPath);
  const prefersDark = useMediaQuery('(prefers-color-scheme: dark)', { noSsr: true });
  const [override, setOverride] = useState(storedMode);
  const mode = override ?? (prefersDark ? 'dark' : 'light');

  useEffect(() => {
    const update = () => setActivePage(pageFromPath());
    window.addEventListener('popstate', update);
    return () => window.removeEventListener('popstate', update);
  }, []);

  const isRtl = i18n.language === 'ar';
  const direction = isRtl ? 'rtl' : 'ltr';

  const theme = useMemo(() => createConsoleTheme(mode, direction), [mode, direction]);
  const cache = useMemo(() => (isRtl ? createRtlCache() : createLtrCache()), [isRtl]);

  useEffect(() => {
    document.documentElement.dir = direction;
    document.documentElement.lang = i18n.language;
  }, [direction, i18n.language]);

  function navigate(page: PageKey) {
    history.pushState(null, '', '/' + page);
    setActivePage(page);
  }

  function toggleMode() {
    const next = mode === 'light' ? 'dark' : 'light';
    setOverride(next);
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      // Storage can be unavailable in a private browsing context.
    }
  }

  return (
    <CacheProvider value={cache}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <ConsoleHeader page={activePage} mode={mode} onNavigate={navigate} onToggleMode={toggleMode} />
        <Container key={activePage} maxWidth="lg" component="main" className="etis-page-in"
          sx={{ px: { xs: 4, sm: 6 }, pt: { xs: 5, sm: 8 }, pb: 12 }}>
          {activePage === 'scan' && <ScanPage />}
          {activePage === 'threats' && <ThreatFeedPage />}
          {activePage === 'stats' && <StatsPage />}
          {activePage === 'incidents' && <IncidentsPage />}
          {activePage === 'files' && <FileScansPage />}
          {activePage === 'network' && <NetworkWindowsPage />}
          {activePage === 'indicators' && <IndicatorsPage />}
          {activePage === 'attack' && <AttackPage />}
        </Container>
      </ThemeProvider>
    </CacheProvider>
  );
}
