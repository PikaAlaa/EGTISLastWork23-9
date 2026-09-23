import React from 'react'
import ReactDOM from 'react-dom/client'
import { CacheProvider } from '@emotion/react'
import createCache from '@emotion/cache'
import { CssBaseline, ThemeProvider, createTheme } from '@mui/material'
import rtlPlugin from 'stylis-plugin-rtl'
import { prefixer } from 'stylis'
import './i18n'
import './styles.css'
import App from './App'

const rtlCache = createCache({ key: 'etis-rtl', stylisPlugins: [prefixer, rtlPlugin] })
const ltrCache = createCache({ key: 'etis-ltr' })

function Root() {
  const [direction, setDirection] = React.useState<'rtl' | 'ltr'>('rtl')
  const theme = React.useMemo(() => createTheme({
    direction,
    palette: { mode: 'dark', primary: { main: '#37d6c0' }, secondary: { main: '#ffbd59' }, background: { default: '#061321', paper: '#0d2438' } },
    typography: { fontFamily: direction === 'rtl' ? 'Tahoma, Arial, sans-serif' : 'Inter, Arial, sans-serif' },
    shape: { borderRadius: 16 },
  }), [direction])
  return <CacheProvider value={direction === 'rtl' ? rtlCache : ltrCache}><ThemeProvider theme={theme}><CssBaseline/><App direction={direction} onDirectionChange={setDirection}/></ThemeProvider></CacheProvider>
}

ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><Root/></React.StrictMode>)
