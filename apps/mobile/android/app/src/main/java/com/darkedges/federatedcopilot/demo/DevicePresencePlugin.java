package com.darkedges.federatedcopilot.demo;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/** Local hardware spike, not a PF login or a backend enrollment authority. */
@CapacitorPlugin(name = "DevicePresence")
public final class DevicePresencePlugin extends Plugin {
    private static final String ALIAS = "com.darkedges.federatedcopilot.device-test.v1";
    private PluginCall pending;
    private BiometricPrompt prompt;

    @Override public void load() {
        // Device-test diagnostics only: fixed fields from this app's own key.
        // No biometric prompt, private/public key bytes, user ID or message text.
        try {
            KeyStore current = store();
            if (current.containsAlias(ALIAS)) metadata(current);
            else Log.i("FCDevicePolicy", "{\"stage\":\"startup\",\"hasKey\":false}");
        } catch (Exception ignored) {
            Log.i("FCDevicePolicy", "{\"stage\":\"startup\",\"policyAccepted\":false}");
        }
    }

    private boolean available() {
        return BiometricManager.from(getContext()).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) == BiometricManager.BIOMETRIC_SUCCESS;
    }
    private KeyStore store() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        return store;
    }
    private static String encode(byte[] bytes) {
        return Base64.encodeToString(bytes, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }
    private JSObject metadata(KeyStore store) throws Exception {
        PrivateKey key = (PrivateKey) store.getKey(ALIAS, null);
        KeyInfo info = KeyFactory.getInstance("EC", "AndroidKeyStore").getKeySpec(key, KeyInfo.class);
        boolean hardware;
        String level;
        if (Build.VERSION.SDK_INT >= 31) {
            int security = info.getSecurityLevel();
            hardware = security == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT || security == KeyProperties.SECURITY_LEVEL_STRONGBOX;
            level = security == KeyProperties.SECURITY_LEVEL_STRONGBOX ? "strongbox" : "tee";
        } else {
            hardware = info.isInsideSecureHardware();
            level = "tee";
        }
        JSObject diagnostic = new JSObject();
        diagnostic.put("stage", "key_policy");
        diagnostic.put("hardware", hardware);
        diagnostic.put("securityLevel", level);
        diagnostic.put("authRequired", info.isUserAuthenticationRequired());
        diagnostic.put("reportedDuration", info.getUserAuthenticationValidityDurationSeconds());
        diagnostic.put("authType", info.getUserAuthenticationType());
        diagnostic.put("invalidatedOnEnrollment", info.isInvalidatedByBiometricEnrollment());
        diagnostic.put("authHardwareEnforced", info.isUserAuthenticationRequirementEnforcedBySecureHardware());
        diagnostic.put("strongBiometricAvailable", available());
        boolean accepted = hardware && info.isUserAuthenticationRequired() && KeyPolicy.perUse(info.getUserAuthenticationValidityDurationSeconds())
            && info.getUserAuthenticationType() == KeyProperties.AUTH_BIOMETRIC_STRONG
            && info.isInvalidatedByBiometricEnrollment() && info.isUserAuthenticationRequirementEnforcedBySecureHardware();
        diagnostic.put("policyAccepted", accepted);
        Log.i("FCDevicePolicy", diagnostic.toString());
        if (!accepted) {
            throw new SecurityException("unsupported_device_key");
        }
        JSObject result = new JSObject();
        result.put("publicKeySpki", encode(store.getCertificate(ALIAS).getPublicKey().getEncoded()));
        result.put("securityLevel", level);
        return result;
    }
    @PluginMethod
    public void getStatus(PluginCall call) {
        try {
            KeyStore store = store();
            boolean hasKey = store.containsAlias(ALIAS);
            JSObject result = new JSObject();
            result.put("available", available());
            result.put("hasKey", hasKey);
            result.put("securityLevel", hasKey ? metadata(store).getString("securityLevel") : "unknown");
            call.resolve(result);
        } catch (Exception ignored) { call.reject("Device key unavailable", "device_key_unavailable"); }
    }
    @PluginMethod
    public void createKey(PluginCall call) {
        getActivity().runOnUiThread(() -> {
            try {
                if (!available() || pending != null) throw new SecurityException();
                KeyStore store = store();
                // Never replace an existing/invalidated key without a new enrollment decision.
                if (!store.containsAlias(ALIAS)) {
                    KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
                    generator.initialize(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setUserAuthenticationRequired(true)
                        .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                        .setInvalidatedByBiometricEnrollment(true)
                        .build());
                    generator.generateKeyPair();
                }
                call.resolve(metadata(store));
            } catch (Exception ignored) { call.reject("Hardware biometric key unavailable", "device_key_unavailable"); }
        });
    }
    @PluginMethod
    public void signChallenge(PluginCall call) {
        final String challenge = call.getString("challenge");
        final byte[] message;
        try { message = DeviceChallenge.message(challenge); }
        catch (Exception ignored) { call.reject("Invalid device challenge", "invalid_device_challenge"); return; }
        getActivity().runOnUiThread(() -> {
            try {
                if (!available() || pending != null) throw new SecurityException();
                KeyStore store = store();
                JSObject keyMetadata = metadata(store);
                Signature signature = Signature.getInstance("SHA256withECDSA");
                signature.initSign((PrivateKey) store.getKey(ALIAS, null));
                pending = call;
                prompt = new BiometricPrompt((FragmentActivity) getActivity(), ContextCompat.getMainExecutor(getContext()),
                    new BiometricPrompt.AuthenticationCallback() {
                        @Override public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                            if (pending != call) return;
                            pending = null; prompt = null;
                            try {
                                if (result.getCryptoObject() == null || result.getCryptoObject().getSignature() != signature) throw new SecurityException();
                                signature.update(message);
                                JSObject proof = new JSObject();
                                proof.put("challenge", challenge);
                                proof.put("publicKeySpki", keyMetadata.getString("publicKeySpki"));
                                proof.put("signature", encode(signature.sign()));
                                proof.put("algorithm", "SHA256withECDSA-DER");
                                call.resolve(proof);
                            } catch (Exception ignored) { call.reject("Device proof unavailable", "device_proof_unavailable"); }
                        }
                        @Override public void onAuthenticationError(int code, @NonNull CharSequence ignored) {
                            if (pending != call) return;
                            pending = null; prompt = null;
                            call.reject("Fingerprint unlock not completed", "biometric_not_completed");
                        }
                    });
                BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Unlock Federated Copilot device test")
                    .setSubtitle("Sign a one-use local test challenge")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .setNegativeButtonText("Cancel")
                    .build();
                prompt.authenticate(info, new BiometricPrompt.CryptoObject(signature));
            } catch (Exception ignored) {
                if (pending == call) { pending = null; prompt = null; }
                call.reject("Device proof unavailable", "device_proof_unavailable");
            }
        });
    }
    private void cancelPending() {
        PluginCall call = pending;
        BiometricPrompt oldPrompt = prompt;
        pending = null; prompt = null;
        if (oldPrompt != null) oldPrompt.cancelAuthentication();
        if (call != null) call.reject("Device locked", "device_locked");
    }
    @PluginMethod
    public void lock(PluginCall call) { getActivity().runOnUiThread(() -> { cancelPending(); call.resolve(); }); }
    @Override protected void handleOnStop() { cancelPending(); }
    @Override protected void handleOnDestroy() { cancelPending(); }
}
