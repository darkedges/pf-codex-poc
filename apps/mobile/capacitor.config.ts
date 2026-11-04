import type {CapacitorConfig} from '@capacitor/cli';
const config:CapacitorConfig={
 appId:'com.darkedges.federatedcopilot.demo',appName:'Federated Copilot',webDir:'dist',
 loggingBehavior:'none',
 android:{allowMixedContent:false,webContentsDebuggingEnabled:false,loggingBehavior:'none'},
 server:{androidScheme:'https',cleartext:false,allowNavigation:[]}
};
export default config;
