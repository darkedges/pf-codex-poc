import {useState} from 'react';
import {IonButton} from '@ionic/react';
type Props={report:string;eventCount:number};
/** Deliberately local and user copied. No diagnostic upload or analytics. */
export function SignInDiagnosticsPanel({report,eventCount}:Props){
 const [notice,setNotice]=useState('');
 const copy=async()=>{try{if(!navigator.clipboard?.writeText)throw Error();await navigator.clipboard.writeText(report);setNotice('Report copied. You can paste it into this support chat.');}catch{setNotice('Touch and hold the report below, then select all and copy.');}};
 return <details className="signin-diagnostics"><summary>Sign-in diagnostics · v9</summary>
  <p>Tap Sign in once, then copy this report. It contains step names, timing and fixed error codes. It does not contain passwords, tokens, keys or login URLs. Nothing is uploaded automatically.</p>
  <p role="status">{eventCount?`${eventCount} diagnostic events recorded.`:'No sign-in attempt recorded in this app session.'}</p>
  <IonButton size="small" fill="outline" onClick={()=>void copy()} disabled={!eventCount}>Copy diagnostic report</IonButton>
  {notice&&<p role="status">{notice}</p>}
  <textarea aria-label="Sign-in diagnostic report" readOnly rows={10} value={report} spellCheck={false}/>
 </details>;
}
