import {useEffect,useState} from 'react';
import {IonApp,IonPage,IonHeader,IonToolbar,IonContent,IonButton,IonFooter,IonTextarea,IonSpinner,IonCheckbox} from '@ionic/react';
import {App as CapacitorApp} from '@capacitor/app';
import {createMobileController,mobileOrigin} from './mobile-runtime.ts';
import {listenForMobileReturn} from './app-return.ts';
import {SignInDiagnosticsPanel} from './SignInDiagnosticsPanel.tsx';

/** Explicit live build only. Failed services never switch to device-test responses. */
export function LiveApp(){
 const [controller]=useState(createMobileController),[state,setState]=useState(controller.snapshot()),[draft,setDraft]=useState(''),[sending,setSending]=useState(false);
 useEffect(()=>{
  const unsubscribe=controller.subscribe(()=>{const next=controller.snapshot();setState(next);if(next.phase!=='chat'){setDraft('');setSending(false);}});
  void controller.initialize();
  const background=()=>{if(document.visibilityState==='hidden')void controller.background();};document.addEventListener('visibilitychange',background);
  const lifecycle=CapacitorApp.addListener('appStateChange',s=>{if(!s.isActive)void controller.background();}).catch(()=>null);
  return()=>{unsubscribe();document.removeEventListener('visibilitychange',background);void lifecycle.then(v=>v?.remove());void controller.cancelSignIn();};
 },[controller]);
 useEffect(()=>{
  if(state.phase!=='browser')return;
  // Do not replay the original launch Intent when starting another sign-in.
  const listener=listenForMobileReturn(mobileOrigin,async handoff=>controller.handleReturn(mobileOrigin+'/mobile/return?handoff='+handoff),undefined,false).catch(()=>null);
  return()=>{void listener.then(remove=>remove?.());};
 },[controller,state.phase]);
 const busy=state.phase==='starting'||state.phase==='completing';
 const send=async()=>{if(!draft.trim()||sending)return;const text=draft;setDraft('');setSending(true);try{await controller.send(text);}catch{}finally{setSending(false);}};
 return <IonApp><IonPage>
  <IonHeader className="ion-no-border"><IonToolbar><div className="brand"><span className="brand-mark">f<span>c</span></span><div><strong>Federated Copilot</strong><small>YOUR WORK, IN CONVERSATION</small></div><span className="test-tag">LIVE PREVIEW</span></div></IonToolbar></IonHeader>
  <IonContent className="app-content">
   {state.phase!=='chat'?<main className="welcome">
    <div className="eyebrow">PRIVATE BY DESIGN</div><h1>{state.phase==='consent'?(state.resourceRevoked?'Access revoked.':'Review your access.') :<>A fresh chat.<br/>Every time.</>}</h1>
    <p>{state.phase==='consent'?(state.resourceRevoked?'This enrollment cannot restore the revoked permission. Sign in again to review and approve new access.':state.resourceDescription):state.phase==='browser'?'Complete sign-in in your system browser. Return here to confirm this device with your fingerprint.':'Sign in once to connect your device. Use your fingerprint to open a new chat when you return.'}</p>
    <p>Device enrollment lasts up to 30 days. Every unlock still checks current access. Chats are cleared when this app goes into the background.</p>
    {state.error&&<p role="alert">{state.error}</p>}
    {!busy&&state.phase!=='browser'&&!state.resourceRevoked&&<div className="consent-choice"><IonCheckbox checked={state.autoApprove} labelPlacement="end" onIonChange={e=>void controller.setAutoApprove(e.detail.checked).catch(()=>{})}>Automatically approve configured document and chat access</IonCheckbox><small>On by default. Turning this off asks before new approvals; existing access remains until revoked.</small></div>}
    {busy?<p role="status"><IonSpinner/> Preparing your session…</p>:state.phase==='browser'?<IonButton expand="block" onClick={()=>void controller.cancelSignIn()}>Cancel sign-in</IonButton>:state.phase==='consent'?<>
     {state.resourceRevoked?<IonButton expand="block" onClick={()=>void controller.signIn(true)}>Sign in again</IonButton>:<><IonButton expand="block" onClick={()=>void controller.approveAccess()}>Approve access</IonButton><IonButton expand="block" fill="clear" onClick={()=>void controller.background()}>Not now</IonButton></>}
    </>:<>
     {state.enrolled&&<IonButton expand="block" onClick={()=>void controller.unlock()}>Unlock with fingerprint</IonButton>}
     <IonButton expand="block" fill={state.enrolled?'outline':'solid'} onClick={()=>void controller.signIn(state.enrolled||state.phase==='error')}>{state.enrolled||state.phase==='error'?'Sign in again':'Sign in'}</IonButton>
    </>}
    <SignInDiagnosticsPanel report={controller.diagnosticReport()} eventCount={state.diagnostics.events.length}/>
    <small>Preview: live services must be configured. Provider tokens stay on the server; Microsoft tool-trace protection remains unverified for this PoC.</small>
   </main>:<main className="chat-screen"><div className="eyebrow">YOUR SESSION</div>
    {!state.messages.length&&<><h1>A clean slate.</h1><p>Ask about documents your current access permits.</p></>}
    <div className="messages" role="log" aria-live="polite">{state.messages.map(message=><article key={message.id} className={'message '+message.role}><span>{message.role==='user'?'YOU':'COPILOT'}</span><p>{message.text}</p></article>)}</div>
    {sending&&<p role="status"><IonSpinner/> Waiting for a response…</p>}
   </main>}
  </IonContent>
  <IonFooter className="ion-no-border"><div className="composer-footer">{state.phase==='chat'?<><div className="composer"><IonTextarea aria-label="Message" placeholder="Ask a question" value={draft} maxlength={2000} disabled={sending} onIonInput={e=>setDraft(e.detail.value??'')}/><IonButton disabled={sending||!draft.trim()} onClick={()=>void send()}>Send</IonButton></div><div className="session-actions"><IonButton fill="clear" onClick={()=>void controller.background()}>Lock</IonButton><IonButton fill="clear" color="danger" onClick={()=>void controller.revokeAccess().catch(()=>{})}>Revoke access</IonButton></div></>:<p>Approved resources only · No chat history on this device</p>}</div></IonFooter>
 </IonPage></IonApp>;
}
