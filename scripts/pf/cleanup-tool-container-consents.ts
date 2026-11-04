// Owner-authenticated cleanup for this runner's isolated synthetic grants only.
import {resolve,sep} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {startConsent} from './run-consent.mjs';
import {LocalBrowser,forms} from '../../tests/live/local-browser.mjs';
import {local,read} from './common.mjs';
import {profile} from './config.mjs';
const run=resolve(process.env.TOOL_CONTAINER_RUN_DIR??'');
if(!run.startsWith(resolve(local,'tool-container-tests')+sep)||process.env.POLICY_DATABASE!==resolve(run,'policy.sqlite'))throw Error('Explicit isolated cleanup required');
const active=()=>{const db=new DatabaseSync(process.env.POLICY_DATABASE!,{readOnly:true});try{return db.prepare("SELECT g.id FROM grants g JOIN consents c ON c.grant_id=g.id WHERE g.state='active'").all();}finally{db.close();}};
let portal:any;
try{
 const grants=active();if(grants.length>20)throw Error('Unexpected cleanup scope');
 if(grants.length){
  portal=await startConsent();
  // Use fresh owner proof/CSRF for each grant; never broaden to admin authority.
  for(const grant of grants){
   const b=new LocalBrowser(portal.origin),home=await b.request(portal.origin+'/');
   const login=await b.submit(forms(home.html).find(f=>f.action==='/login'));
   const approval=await b.submit(forms(login.html).find(f=>'pf.pass'in f.fields),{'pf.username':profile.human,'pf.pass':read('login-password'),'pf.ok':'clicked'});
   const review=await b.submit(forms(approval.html).find(f=>'pf.oauth.authz.consent'in f.fields),{'pf.oauth.authz.consent':'allow'});
   const form=forms(review.html).find(f=>f.action==='/revoke'&&f.fields.grantId===grant.id);
   if(!form||(await b.submit(form,{},{noRedirect:true})).status!==303)throw Error('Owner cleanup denied');
  }
 }
 if(active().length)throw Error('Owner cleanup incomplete');
 console.log(JSON.stringify({ownerAuthenticatedCleanup:true,revokedCount:grants.length}));
}catch{console.error('Isolated owner cleanup failed');process.exitCode=1;}
finally{if(portal)await portal.stop();}
