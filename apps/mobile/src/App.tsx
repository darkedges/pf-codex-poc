import {useEffect,useState} from 'react';import {IonApp,IonPage,IonHeader,IonToolbar,IonContent,IonButton,IonFooter,IonTextarea,IonSpinner} from '@ionic/react';
import {App as CapacitorApp} from '@capacitor/app';import {nativeDevice} from './native-device.ts';import {verifyDeviceProof} from './proof.ts';import {DeviceTestSession} from './session.ts';
function Fingerprint(){return <svg viewBox="0 0 64 64" fill="none" aria-hidden="true"><path d="M17 27a16 16 0 0 1 30 8c0 10-2 16-5 21M10 33C10 20 19 11 32 11s22 9 22 22M24 51c2-5 2-11 2-16a6 6 0 0 1 12 0c0 13-1 19-4 25M17 35c0 9-1 14-3 19M32 23c-7 0-12 5-12 12m12 0c0 10 0 15-2 20M51 43c-1 5-2 10-4 15" stroke="currentColor" strokeWidth="3" strokeLinecap="round"/></svg>;}
export function App(){
 const [session]=useState(()=>new DeviceTestSession(nativeDevice,verifyDeviceProof)),[state,setState]=useState(session.snapshot()),[draft,setDraft]=useState('');
 useEffect(()=>{
  const unsubscribe=session.subscribe(()=>{const next=session.snapshot();setState(next);if(next.phase!=='chat')setDraft('');});
  const visibility=()=>{if(document.visibilityState==='hidden')void session.lock();};document.addEventListener('visibilitychange',visibility);
  const listener=CapacitorApp.addListener('appStateChange',s=>{if(!s.isActive)void session.lock();}).catch(()=>null);
  return()=>{unsubscribe();document.removeEventListener('visibilitychange',visibility);void listener.then(h=>h?.remove());void session.lock();};
 },[session]);
 const send=()=>{if(!draft.trim())return;try{session.send(draft);setDraft('');}catch{/* Invalid input never creates a message. */}};
 return <IonApp><IonPage>
  <IonHeader className="ion-no-border"><IonToolbar><div className="brand"><span className="brand-mark">f<span>c</span></span><div><strong>Federated Copilot</strong><small>YOUR WORK, IN CONVERSATION</small></div><span className="test-tag">DEVICE TEST</span></div></IonToolbar></IonHeader>
  <IonContent className="app-content">
   {state.phase!=='chat'?<main className="welcome">
    <div className="eyebrow"><span className="status-dot"/> PRIVATE BY DESIGN</div>
    <h1>A fresh chat.<br/>Every time.</h1><p className="intro">Unlock with your fingerprint.<br/>Leave the previous conversation behind.</p>
    <div className="unlock-card"><div className="fingerprint"><Fingerprint/></div><h2>{state.phase==='unlocking'?'Confirm your fingerprint':'Your device. Your access.'}</h2><p>This build tests a hardware-protected Android key. It does not sign you in to PF or connect to Copilot.</p>
     <IonButton expand="block" onClick={()=>{void session.unlock().catch(()=>{});}} disabled={state.phase==='unlocking'}>{state.phase==='unlocking'?<><IonSpinner name="crescent"/> Waiting for fingerprint</>:'Test fingerprint unlock'}</IonButton>
     {state.phase==='unlocking'&&<IonButton fill="clear" expand="block" onClick={()=>{void session.lock();}}>Cancel</IonButton>}
     {state.error&&<p role="alert" className="error-message">{state.error}</p>}
    </div>
    <div className="principles"><div><span>01</span><p><strong>Biometric key protection</strong><br/>A signature is verified before this test chat opens.</p></div><div><span>02</span><p><strong>No saved chat history</strong><br/>Locking the app clears the current conversation.</p></div><div><span>03</span><p><strong>Live sign-in comes next</strong><br/>The planned PF sign-in fallback is not connected yet.</p></div></div>
    <p className="device-note">Android device required · Fingerprint data stays on your phone</p>
   </main>:<main className="chat">
    <div className="chat-heading"><div><div className="eyebrow"><span className="status-dot"/> SIGNATURE VERIFIED LOCALLY</div><h1>New device-test chat</h1></div><IonButton fill="outline" size="small" onClick={()=>{void session.lock();}}>Lock</IonButton></div>
    <div className="test-notice" role="note"><strong>Local test, not Copilot</strong><p>No PF session, Microsoft connection or document access. Messages stay in memory and are cleared when the app locks.</p></div>
    {state.messages.length===0&&<div className="empty-chat"><span className="chat-symbol">✦</span><h2>A clean slate.</h2><p>Send a message to test the chat screen.<br/>Then lock and unlock to check that it is gone.</p></div>}
    <div className="messages" role="log" aria-label="Device-test messages">{state.messages.map(m=><div className={'message '+m.role} key={m.id}><span>{m.role==='user'?'YOU':'DEVICE TEST'}</span><p>{m.text}</p></div>)}</div>
   </main>}
  </IonContent>
  {state.phase==='chat'&&<IonFooter className="ion-no-border composer-footer"><div className="composer"><IonTextarea aria-label="Message for local device test" placeholder="Message this device test…" value={draft} maxlength={2000} autoGrow rows={1} onIonInput={e=>setDraft(String(e.detail.value??''))}/><IonButton aria-label="Send test message" disabled={!draft.trim()} onClick={send}>Send</IonButton></div><p>Device test only · No message history is saved</p></IonFooter>}
 </IonPage></IonApp>;
}
