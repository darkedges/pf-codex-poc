package com.darkedges.federatedcopilot.demo;
import org.junit.Test;
import static org.junit.Assert.*;
public class KeyPolicyTest {
    @Test public void keyInfoUsesMinusOneForPerOperationAuthentication() { assertTrue(KeyPolicy.perUse(-1)); }
    @Test public void keystore2ZeroTimeoutIsAlsoPerOperationAuthentication() { assertTrue(KeyPolicy.perUse(0)); }
    @Test public void timeWindowsAndUnknownValuesAreRejected() { for (int value : new int[]{1, 5, 300, -2}) assertFalse(KeyPolicy.perUse(value)); }
}
