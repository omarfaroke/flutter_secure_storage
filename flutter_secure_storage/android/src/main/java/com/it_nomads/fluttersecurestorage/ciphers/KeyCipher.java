package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public interface KeyCipher {
    // For symmetric keys
    Cipher getCipher(Context context) throws Exception;

    void deleteKey() throws Exception;

    // For asymmetric keys
    byte[] wrap(Key key) throws Exception;
    Key unwrap(byte[] wrappedKey, String algorithm) throws Exception;

    /**
     * True when values (or a legacy wrapped app key) are protected by an Android Keystore AES key.
     */
    default boolean usesKeystoreAesKey() {
        return false;
    }

    /**
     * Returns the non-extractable Keystore AES key when {@link #usesKeystoreAesKey()} is true.
     */
    default SecretKey getKeystoreAesKey() throws Exception {
        throw new UnsupportedOperationException("Not a Keystore AES key cipher");
    }

    /**
     * True when the wrapping key requires a CryptoObject for every use ({@code timeout == 0}).
     * Those keys let BiometricPrompt skip the UI after the first success in a process.
     */
    default boolean isUserAuthenticationBoundToEveryUse() {
        return false;
    }

    /**
     * True when the Keystore key must be unlocked via a CryptoObject-bound biometric prompt
     * before Cipher.init can succeed (including short auth-validity windows).
     */
    default boolean requiresCryptoObjectUnlock() {
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
