package com.darkedges.federatedcopilot.demo;
import android.content.Intent;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ResolveInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.SystemClock;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** No WebView login, shared preferences, provider tokens or secret logging. */
@CapacitorPlugin(name="BrowserLogin")
public final class BrowserLoginPlugin extends Plugin {
    private final PendingLogin pending=new PendingLogin();
    private boolean browserOpened;
    private void clearAttempt(String attemptId) {
        PendingLogin.PublicState current=pending.status(SystemClock.elapsedRealtime());
        if(current!=null && current.attemptId.equals(attemptId)) { pending.clear();browserOpened=false; }
    }
    private SharedPreferences reference() { return getContext().getSharedPreferences("mobile_enrollment_reference_v1",Context.MODE_PRIVATE); }
    private SharedPreferences preferences() { return getContext().getSharedPreferences("mobile_preferences_v1",Context.MODE_PRIVATE); }
    @PluginMethod public void getConsentPreference(PluginCall call) {
        try { JSObject result=new JSObject();result.put("enabled",preferences().getBoolean("autoApproveResources",true));call.resolve(result); }
        catch(Exception ignored) { call.reject("Consent preference unavailable","mobile_preference_unavailable"); }
    }
    @PluginMethod public void setConsentPreference(PluginCall call) {
        try { Boolean enabled=call.getBoolean("enabled");if(enabled==null || !preferences().edit().putBoolean("autoApproveResources",enabled).commit()) throw new SecurityException();call.resolve(); }
        catch(Exception ignored) { call.reject("Consent preference unavailable","mobile_preference_unavailable"); }
    }
    private String deviceHash() throws Exception { return PendingLogin.encode(MessageDigest.getInstance("SHA-256").digest(deviceKey().getBytes(StandardCharsets.UTF_8))); }
    private String deviceKey() throws Exception {
        KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);
        return PendingLogin.encode(store.getCertificate("com.darkedges.federatedcopilot.mobile-presence.v1").getPublicKey().getEncoded());
    }
    private JSObject status(PendingLogin.PublicState state) {
        JSObject result=new JSObject();result.put("pending",state!=null);
        if(state!=null) { result.put("attemptId",state.attemptId);result.put("devicePublicKeySpki",state.deviceKey);result.put("claimHash",state.claimHash);result.put("expiresInMs",Math.max(0,state.expiresAtElapsed-SystemClock.elapsedRealtime())); }
        return result;
    }
    @PluginMethod public void beginLogin(PluginCall call) {
        getActivity().runOnUiThread(()->{
            try { browserOpened=false;call.resolve(status(pending.begin(deviceKey(),SystemClock.elapsedRealtime()))); }
            catch(Exception ignored) { pending.clear();call.reject("Sign-in unavailable","mobile_login_unavailable"); }
        });
    }
    @PluginMethod public void getPendingLogin(PluginCall call) { call.resolve(status(pending.status(SystemClock.elapsedRealtime()))); }
    @PluginMethod public void openLogin(PluginCall call) {
        getActivity().runOnUiThread(()->{
            String failureCode="mobile_browser_state_unavailable";
            try {
                PendingLogin.PublicState state=pending.status(SystemClock.elapsedRealtime());
                if(state==null || browserOpened || !state.attemptId.equals(call.getString("attemptId")) || !state.deviceKey.equals(deviceKey())) throw new SecurityException();
                failureCode="mobile_browser_url_rejected";
                String url=BrowserPolicy.authorization(call.getString("authorizationUrl"));
                failureCode="mobile_browser_missing";
                PackageManager manager=getContext().getPackageManager();
                // Inspect generic HTTPS handling, never resolve the sensitive PF URL.
                Intent probe=new Intent(Intent.ACTION_VIEW,Uri.parse("https://browser-selection.invalid/"));probe.addCategory(Intent.CATEGORY_BROWSABLE);
                List<BrowserSelection.Candidate> candidates=new ArrayList<>();
                for(ResolveInfo match:manager.queryIntentActivities(probe,PackageManager.MATCH_DEFAULT_ONLY|PackageManager.GET_RESOLVED_FILTER))if(match.activityInfo!=null){
                    boolean generic=match.filter!=null&&BrowserSelection.genericHttps(match.filter.hasDataScheme("https"),match.filter.countDataAuthorities(),match.filter.countDataPaths(),match.filter.countDataSchemeSpecificParts());
                    candidates.add(new BrowserSelection.Candidate(match.activityInfo.packageName,generic,match.activityInfo.exported,match.activityInfo.enabled));
                }
                List<String> packages=BrowserSelection.packages(candidates,getContext().getPackageName());
                if(packages.isEmpty())throw new SecurityException();
                ResolveInfo resolved=manager.resolveActivity(probe,PackageManager.MATCH_DEFAULT_ONLY);
                String preferred=resolved!=null&&resolved.activityInfo!=null?resolved.activityInfo.packageName:null;
                Intent intent=new Intent(Intent.ACTION_VIEW,Uri.parse(url));intent.addCategory(Intent.CATEGORY_BROWSABLE);
                if(packages.contains(preferred))intent.setPackage(preferred);
                else if(packages.size()==1)intent.setPackage(packages.get(0));
                else {
                    intent.setPackage(packages.get(0));
                    Intent chooser=Intent.createChooser(intent,"Choose a browser for sign-in");
                    Intent[] others=new Intent[packages.size()-1];
                    for(int i=1;i<packages.size();i++){Intent choice=new Intent(Intent.ACTION_VIEW,Uri.parse(url));choice.addCategory(Intent.CATEGORY_BROWSABLE);choice.setPackage(packages.get(i));others[i-1]=choice;}
                    chooser.putExtra(Intent.EXTRA_INITIAL_INTENTS,others);intent=chooser;
                }
                failureCode="mobile_browser_launch_failed";
                browserOpened=true;getActivity().startActivity(intent);call.resolve();
            } catch(Exception ignored) { clearAttempt(call.getString("attemptId"));call.reject("Browser sign-in could not be opened",failureCode); }
        });
    }
    @PluginMethod public void consumeReturn(PluginCall call) {
        getActivity().runOnUiThread(()->{
            try {
                String handoff=BrowserPolicy.handoff(call.getString("returnUrl"));
                PendingLogin.PublicState state=pending.status(SystemClock.elapsedRealtime());
                if(state==null || !state.attemptId.equals(call.getString("attemptId")) || !browserOpened || !state.deviceKey.equals(deviceKey())) throw new SecurityException();
                String secret=pending.consume(call.getString("attemptId"),SystemClock.elapsedRealtime());browserOpened=false;
                JSObject result=new JSObject();result.put("handoff",handoff);result.put("claimSecret",secret);result.put("devicePublicKeySpki",state.deviceKey);call.resolve(result);
            } catch(Exception ignored) { clearAttempt(call.getString("attemptId"));call.reject("Start sign-in again","mobile_login_unavailable"); }
        });
    }
    @PluginMethod public void cancelLogin(PluginCall call) { getActivity().runOnUiThread(()->{pending.clear();browserOpened=false;call.resolve();}); }
    @PluginMethod public void getEnrollmentReference(PluginCall call) {
        JSObject result=new JSObject();result.put("enrolled",false);
        try {
            SharedPreferences p=reference();String id=p.getString("enrollmentId",null);long expires=p.getLong("expiresAt",0);
            if(id!=null && id.equals(deviceHash()) && expires>System.currentTimeMillis()) { result.put("enrolled",true);result.put("enrollmentId",id);result.put("enrollmentExpiresAt",expires); }
        } catch(Exception ignored) { /* Unknown metadata is not authority; require a fresh sign-in. */ }
        call.resolve(result);
    }
    @PluginMethod public void saveEnrollmentReference(PluginCall call) {
        try {
            String id=call.getString("enrollmentId");Long expires=call.getLong("enrollmentExpiresAt");long now=System.currentTimeMillis();
            if(id==null || !id.equals(deviceHash()) || expires==null || expires<=now || expires>now+30L*86400000L) throw new SecurityException();
            if(!reference().edit().putString("enrollmentId",id).putLong("expiresAt",expires).commit()) throw new SecurityException();
            call.resolve();
        } catch(Exception ignored) { call.reject("Device reference unavailable","mobile_reference_unavailable"); }
    }
    @PluginMethod public void forgetLocalEnrollment(PluginCall call) {
        getActivity().runOnUiThread(()->{
            try {
                pending.clear();browserOpened=false;
                if(!reference().edit().clear().commit()) throw new SecurityException();
                KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);store.deleteEntry("com.darkedges.federatedcopilot.mobile-presence.v1");call.resolve();
            } catch(Exception ignored) { call.reject("Device reset unavailable","mobile_reference_unavailable"); }
        });
    }
    // Stop is intentional during external-browser login; destroy/process loss requires new sign-in.
    @Override protected void handleOnDestroy() { pending.clear();browserOpened=false; }
}
