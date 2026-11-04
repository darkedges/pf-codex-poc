package com.darkedges.federatedcopilot.demo;
final class KeyPolicy {
    private KeyPolicy() {}
    // Legacy KeyInfo documents -1; Keystore2 reports zero when no timeout is set.
    // Both mean no grace window. Positive windows and other negatives fail closed.
    static boolean perUse(int reportedDuration) { return reportedDuration == -1 || reportedDuration == 0; }
}
