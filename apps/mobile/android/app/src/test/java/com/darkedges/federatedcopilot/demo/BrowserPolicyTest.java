package com.darkedges.federatedcopilot.demo;
import org.junit.Test;
import static org.junit.Assert.*;
public class BrowserPolicyTest {
    @Test public void onlyPinnedParAuthorizationCanBeOpened() {
        String url = "https://pf-a.copilot.darkedges.com/as/authorization.oauth2?client_id=mobile-bff&request_uri=urn%3Afixture";
        assertEquals(url, BrowserPolicy.authorization(url));
        for (String input : new String[]{"http://pf-a.copilot.darkedges.com/as/authorization.oauth2?client_id=x&request_uri=urn:x", "https://evil.test/auth", url + "&redirect_uri=https://evil.test", url + "#fragment", url.replace("client_id=", "scope="), url.replace("request_uri=urn%3Afixture", "request_uri=https%3A%2F%2Fevil.test"), url + "&client_id=other"}) {
            try { BrowserPolicy.authorization(input); fail("accepted unsafe browser destination"); } catch (IllegalArgumentException expected) {}
        }
    }
    @Test public void onlyExactCanonicalAppReturnsAreAccepted() {
        String handoff = new String(new char[42]).replace('\0','a') + "A";
        assertEquals(handoff, BrowserPolicy.handoff("https://agent.copilot.darkedges.com/mobile/return?handoff=" + handoff));
        for (String input : new String[]{"https://evil.test/mobile/return?handoff=" + handoff, "https://agent.copilot.darkedges.com/mobile/return?handoff=" + handoff + "&extra=x", "https://agent.copilot.darkedges.com/mobile/return?handoff=" + handoff + "#x"}) {
            try { BrowserPolicy.handoff(input); fail("accepted unsafe return"); } catch (IllegalArgumentException expected) {}
        }
    }
}
