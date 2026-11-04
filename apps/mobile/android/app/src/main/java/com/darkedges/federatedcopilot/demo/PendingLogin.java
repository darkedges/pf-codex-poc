package com.darkedges.federatedcopilot.demo;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

/** In-process custody only. No disk, token, user identity or sliding lifetime. */
final class PendingLogin {
    static final class PublicState {
        final String attemptId, deviceKey, claimHash;
        final long expiresAtElapsed;
        PublicState(String id, String key, String hash, long expires) { attemptId=id; deviceKey=key; claimHash=hash; expiresAtElapsed=expires; }
    }
    private byte[] secret;
    private PublicState state;
    static String encode(byte[] value) { return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
    synchronized PublicState begin(String deviceKey, long now) {
        clear();
        if (deviceKey == null || deviceKey.isEmpty() || deviceKey.length()>1024 || now<0) throw new IllegalArgumentException();
        try {
            secret=new byte[32]; new SecureRandom().nextBytes(secret);
            String encoded=encode(secret);
            String hash=encode(MessageDigest.getInstance("SHA-256").digest(encoded.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            state=new PublicState(UUID.randomUUID().toString(), deviceKey, hash, Math.addExact(now,300000)); return state;
        } catch(Exception ignored) { clear(); throw new IllegalStateException("login_unavailable"); }
    }
    synchronized PublicState status(long now) {
        if (state!=null && (now<0 || now>=state.expiresAtElapsed)) clear();
        return state;
    }
    synchronized String consume(String attemptId, long now) {
        PublicState current=status(now);
        try {
            if (current==null || !current.attemptId.equals(attemptId) || secret==null) throw new IllegalStateException("login_unavailable");
            return encode(secret);
        } finally { clear(); }
    }
    synchronized void clear() { if(secret!=null) Arrays.fill(secret,(byte)0); secret=null; state=null; }
}
