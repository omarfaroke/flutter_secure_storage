package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;

import java.security.Key;

import javax.crypto.Cipher;

public interface KeyCipher {
    // For symmetric keys
    Cipher getCipher(Context context) throws Exception;

    void deleteKey() throws Exception;

    // For asymmetric keys
    byte[] wrap(Key key) throws Exception;
    Key unwrap(byte[] wrappedKey, String algorithm) throws Exception;

    /**
     * True when the wrapping key requires a CryptoObject for every use ({@code timeout == 0}).
     * Those keys let BiometricPrompt skip the UI after the first success in a process.
     */
    default boolean isUserAuthenticationBoundToEveryUse() {
        return false;
    }

    /**
     * True when the wrapping key cannot be used even after a successful biometric prompt
     * (for example after a fingerprint was added or removed).
     */
    default boolean isPermanentlyInvalidated() {
        return false;
    }

    /**
     * True when this wrapping key was created with {@code setInvalidatedByBiometricEnrollment(true)}.
     * Those keys should be rewrapped onto a key that survives enrollment changes.
     */
    default boolean isInvalidatedByBiometricEnrollment() {
        return false;
    }
}
