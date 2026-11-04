package com.darkedges.federatedcopilot.demo;
import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.charset.StandardCharsets;
public class DeviceChallengeTest {
    @Test public void onlySpikeChallengesAreDomainSeparated() {
        String challenge = "fc-mobile-spike-v1:" + new String(new char[43]).replace('\0', 'a');
        assertEquals("federated-copilot/device-test/v1\n" + challenge, new String(DeviceChallenge.message(challenge), StandardCharsets.UTF_8));
    }
    @Test public void arbitrarySigningInputsFailClosed() {
        for (String value : new String[]{null, "", "eyJ.header.signature", "https://example.test", "fc-mobile-spike-v1:short", "fc-mobile-spike-v1:" + new String(new char[44]).replace('\0', 'a')}) {
            try { DeviceChallenge.message(value); fail("accepted invalid input"); } catch (IllegalArgumentException expected) {}
        }
    }
}
