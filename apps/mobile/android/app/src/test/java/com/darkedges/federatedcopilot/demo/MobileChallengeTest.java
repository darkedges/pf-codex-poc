package com.darkedges.federatedcopilot.demo;
import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.charset.StandardCharsets;
public class MobileChallengeTest {
    @Test public void onlyLiveEnrollmentAndResumeChallengesAreAccepted() {
        String nonce = new String(new char[43]).replace('\0', 'a');
        for (String purpose : new String[]{"enroll", "resume"}) {
            String c = purpose + ":" + nonce;
            assertEquals("federated-copilot/mobile-presence/v1\n" + c, new String(MobileChallenge.message(c), StandardCharsets.UTF_8));
        }
    }
    @Test public void spikeJwtAndArbitrarySigningInputsAreDenied() {
        for (String c : new String[]{null, "", "enroll:short", "resume:" + new String(new char[44]).replace('\0','a'), "fc-mobile-spike-v1:" + new String(new char[43]).replace('\0','a'), "eyJ.header.signature", "https://example.test"}) {
            try { MobileChallenge.message(c); fail("accepted invalid challenge"); } catch (IllegalArgumentException expected) {}
        }
    }
}
