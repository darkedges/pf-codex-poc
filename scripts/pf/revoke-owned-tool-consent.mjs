import {LocalBrowser,forms} from '../../tests/live/local-browser.mjs';
import {read} from './common.mjs';import {profile} from './config.mjs';
// Fresh owner proof and an exact server-rendered owned-grant form, not admin
// authority or a direct database mutation. Never approves another grant.
export async function revokeOwnedToolConsent(origin,grantId){
 const b=new LocalBrowser(origin),home=await b.request(origin+'/');
 const login=await b.submit(forms(home.html).find(f=>f.action==='/login'));
 const approval=await b.submit(forms(login.html).find(f=>'pf.pass'in f.fields),{'pf.username':profile.human,'pf.pass':read('login-password'),'pf.ok':'clicked'});
 const review=await b.submit(forms(approval.html).find(f=>'pf.oauth.authz.consent'in f.fields),{'pf.oauth.authz.consent':'allow'});
 const form=forms(review.html).find(f=>f.action==='/revoke'&&f.fields.grantId===grantId);
 if(!form||(await b.submit(form,{},{noRedirect:true})).status!==303)throw Error('Fresh owner revocation denied');
}
