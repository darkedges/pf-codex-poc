package com.darkedges.federatedcopilot.demo;
import org.junit.Test;
import static org.junit.Assert.*;
public class PendingLoginTest {
    @Test public void secretIsReturnedOnceAndDoesNotSlideOnAccess() throws Exception {
        PendingLogin p = new PendingLogin();
        PendingLogin.PublicState state = p.begin("device-public-key", 1000);
        assertNotNull(state.claimHash); assertNotNull(state.attemptId);
        assertEquals(state.attemptId, p.status(2000).attemptId);
        String secret = p.consume(state.attemptId, 2000);
        assertEquals(43, secret.length());
        assertEquals(state.claimHash, PendingLogin.encode(java.security.MessageDigest.getInstance("SHA-256").digest(secret.getBytes(java.nio.charset.StandardCharsets.UTF_8))));
        assertNull(p.status(2001));
        try { p.consume(state.attemptId, 2001); fail("replayed secret"); } catch (IllegalStateException expected) {}
    }
    @Test public void expirationCancellationAndWrongAttemptFailClosed() {
        PendingLogin p = new PendingLogin(); PendingLogin.PublicState state = p.begin("key", 10);
        assertNull(p.status(300010));
        try { p.consume(state.attemptId, 300010); fail("expired"); } catch (IllegalStateException expected) {}
        state = p.begin("key", 400000); p.clear(); assertNull(p.status(400001));
        state = p.begin("key", 500000);
        try { p.consume("different-attempt", 500001); fail("other attempt"); } catch (IllegalStateException expected) {}
        assertNull(p.status(500002));
    }
    @Test public void beginningAgainInvalidatesThePreviousAttempt() {
        PendingLogin p = new PendingLogin(); PendingLogin.PublicState first = p.begin("key", 10), second = p.begin("key", 20);
        assertNotEquals(first.attemptId, second.attemptId); assertNotEquals(first.claimHash, second.claimHash);
        assertEquals(second.attemptId, p.status(30).attemptId);
    }
}
