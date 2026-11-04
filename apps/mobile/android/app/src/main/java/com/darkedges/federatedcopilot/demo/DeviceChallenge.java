package com.darkedges.federatedcopilot.demo;

import java.nio.charset.StandardCharsets;

/** The spike key cannot sign JWTs, URLs or another protocol's input. */
final class DeviceChallenge {
    private DeviceChallenge() {}
    static byte[] message(String challenge) {
        if (challenge == null || !challenge.matches("fc-mobile-spike-v1:[A-Za-z0-9_-]{43}")) {
            throw new IllegalArgumentException("invalid_device_challenge");
        }
        return ("federated-copilot/device-test/v1\n" + challenge).getBytes(StandardCharsets.UTF_8);
    }
}
