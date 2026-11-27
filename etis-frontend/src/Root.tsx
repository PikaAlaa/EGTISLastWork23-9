import { Suspense, lazy } from 'react';
import App from './App.tsx';

// Console redesign v1 review page (docs/design/console-redesign-v1.md); lazy so the live console bundle is unchanged.
const DesignPreview = lazy(() => import('./pages/DesignPreview.tsx'));

export default function Root() {
  return location.pathname === '/design-preview'
    ? <Suspense fallback={null}><DesignPreview /></Suspense>
    : <App />;
}
