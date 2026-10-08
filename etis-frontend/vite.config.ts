import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig(({mode}) => {
 const env = loadEnv(mode, '..', '');
 return { plugins:[react()], server:{ host:'127.0.0.1',proxy:{'/api':{
  target:'http://127.0.0.1:8000',rewrite:p=>p.replace(/^\/api/,''),
  headers:env.ETIS_API_KEY?{'X-API-Key':env.ETIS_API_KEY}:{},
 }}}};
});
