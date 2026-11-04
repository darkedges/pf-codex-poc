package com.darkedges.federatedcopilot.demo;
import org.junit.Test;import static org.junit.Assert.*;import java.util.Arrays;import java.util.Collections;
public class BrowserSelectionTest {
    private BrowserSelection.Candidate candidate(String name,boolean browser,boolean exported,boolean enabled){return new BrowserSelection.Candidate(name,browser,exported,enabled);}
    @Test public void noDefaultStillOffersAvailableBrowsers(){assertEquals(Arrays.asList("browser.one","browser.two"),BrowserSelection.packages(Arrays.asList(candidate("browser.one",true,true,true),candidate("browser.two",true,true,true)),"our.app"));}
    @Test public void arbitraryDeepLinkAppsAndOwnOrDisabledActivitiesAreNotBrowserChoices(){assertEquals(Collections.singletonList("browser.safe"),BrowserSelection.packages(Arrays.asList(candidate("interceptor.app",false,true,true),candidate("our.app",true,true,true),candidate("disabled.browser",true,true,false),candidate("private.browser",true,false,true),candidate("browser.safe",true,true,true),candidate("browser.safe",true,true,true)),"our.app"));}
    @Test public void emptyBrowserListFailsWithoutInventingAPackage(){assertTrue(BrowserSelection.packages(Collections.emptyList(),"our.app").isEmpty());}
    @Test public void onlyGenericHttpsFiltersQualify(){assertTrue(BrowserSelection.genericHttps(true,0,0,0));assertFalse(BrowserSelection.genericHttps(false,0,0,0));assertFalse(BrowserSelection.genericHttps(true,1,0,0));assertFalse(BrowserSelection.genericHttps(true,0,1,0));assertFalse(BrowserSelection.genericHttps(true,0,0,1));}
}
