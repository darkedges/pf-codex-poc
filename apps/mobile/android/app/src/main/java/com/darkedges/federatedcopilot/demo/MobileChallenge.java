package com.darkedges.federatedcopilot.demo;
import java.nio.charset.StandardCharsets;

/** Live device presence only; cannot sign JWTs or the local spike protocol. */
final class MobileChallenge {
    private MobileChallenge() {}
    static byte[] message(String challenge) {
        if (challenge == null || !challenge.matches("(enroll|resume):[A-Za-z0-9_-]{43}")) {
            throw new IllegalArgumentException("invalid_mobile_challenge");
        }
        return ("federated-copilot/mobile-presence/v1\n" + challenge).getBytes(StandardCharsets.UTF_8);
    }
}
