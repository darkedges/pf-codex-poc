import React from 'react';import {createRoot} from 'react-dom/client';import {setupIonicReact} from '@ionic/react';
import '@ionic/react/css/core.css';import '@ionic/react/css/normalize.css';import '@ionic/react/css/structure.css';import '@ionic/react/css/typography.css';import './theme.css';
setupIonicReact({mode:'md'});
const Component=import.meta.env.VITE_MOBILE_MODE==='live'?(await import('./LiveApp.tsx')).LiveApp:(await import('./App.tsx')).App;
createRoot(document.getElementById('root')!).render(<Component/>);
