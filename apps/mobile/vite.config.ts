import {defineConfig,loadEnv} from 'vite';
import react from '@vitejs/plugin-react';
import {mobileMode,mobileHtml} from './src/build-mode.ts';
export default defineConfig(({mode})=>{
 const selected=mobileMode(process.env.VITE_MOBILE_MODE??loadEnv(mode,process.cwd(),'VITE_').VITE_MOBILE_MODE);
 return{plugins:[react(),{name:'mobile-content-policy',transformIndexHtml:(html:string)=>mobileHtml(html,selected)}],define:{'import.meta.env.VITE_MOBILE_MODE':JSON.stringify(selected)},server:{host:'127.0.0.1'},build:{sourcemap:false}};
});
