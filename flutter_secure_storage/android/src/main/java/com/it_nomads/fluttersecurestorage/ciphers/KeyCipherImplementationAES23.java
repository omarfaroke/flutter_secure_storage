package com.it_nomads.fluttersecurestorage.ciphers;

import static android.security.keystore.KeyProperties.AUTH_BIOMETRIC_STRONG;
import static android.security.keystore.KeyProperties.AUTH_DEVICE_CREDENTIAL;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Base64;
import android.util.Log;

import com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

public class KeyCipherImplementationAES23 implements KeyCipher {

    private static final String TAG = "AESCipher23";
    private static final String KEYSTORE_PROVIDER_ANDROID = "AndroidKeyStore";
    private static final String SHARED_PREFERENCES_KEY = "KeyStoreIV1";
    private static final int IV_SIZE = 16;
    private static final int KEY_SIZE = 256;
    // Short window so multiple Cipher.init calls (e.g. readAll) can complete after one
    // CryptoObject prompt. The Keystore key remains non-extractable.
    private static final int AUTH_VALIDITY_SECONDS = 5;
    protected final String keyAlias;

    protected final Context context;
    protected final FlutterSecureStorageConfig config;

    public KeyCipherImplementationAES23(Context context, FlutterSecureStorageConfig config) throws Exception {
        this.context = context;
        this.config = config;
        keyAlias = createKeyAlias(context);
        ensureSymmetricKeyAtAlias();
    }

    /**
     * A leftover key of the wrong type must never be used as-is, since Cipher.init would throw
     * deep inside a confusing provider error. Treat that the same as "no key yet".
     */
    private void ensureSymmetricKeyAtAlias() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
        ks.load(null);
        Key existingKey = ks.getKey(keyAlias, null);
        if (existingKey == null) {
            generateSymmetricKey();
        } else if (!(existingKey instanceof SecretKey)) {
            Log.w(TAG, "Alias " + keyAlias + " holds a " + existingKey.getClass().getSimpleName()
                    + ", not a SecretKey, replacing it with a fresh symmetric key");
            ks.deleteEntry(keyAlias);
            generateSymmetricKey();
        }
    }

    @Override
    public byte[] wrap(Key key) throws UnsupportedOperationException {
        throw new UnsupportedOperationException("AES symmetric keys in AndroidKeyStore cannot wrap other keys");
    }

    @Override
    public Key unwrap(byte[] wrappedKey, String algorithm) throws UnsupportedOperationException {
        throw new UnsupportedOperationException("AES symmetric keys in AndroidKeyStore cannot unwrap other keys");
    }

    protected String createKeyAlias(Context context) {
        return context.getPackageName() + ".FlutterSecureStoragePluginKey" + config.getKeyAliasSuffix();
    }

    @Override
    public void deleteKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
        ks.load(null);
        ks.deleteEntry(keyAlias);

        SharedPreferences preferences = context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        preferences.edit().remove(SHARED_PREFERENCES_KEY).apply();
    }

    @Override
    public boolean isUserAuthenticationBoundToEveryUse() {
        try {
            KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
            ks.load(null);
            Key key = ks.getKey(keyAlias, null);
            if (!(key instanceof SecretKey)) {
                return false;
            }
            SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), KEYSTORE_PROVIDER_ANDROID);
            KeyInfo info = (KeyInfo) factory.getKeySpec((SecretKey) key, KeyInfo.class);
            return info.isUserAuthenticationRequired()
                    && info.getUserAuthenticationValidityDurationSeconds() == -1;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * True when this Keystore AES key must be unlocked via a CryptoObject biometric prompt.
     */
    @Override
    public boolean requiresCryptoObjectUnlock() {
        try {
            KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
            ks.load(null);
            Key key = ks.getKey(keyAlias, null);
            if (!(key instanceof SecretKey)) {
                return false;
            }
            SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), KEYSTORE_PROVIDER_ANDROID);
            KeyInfo info = (KeyInfo) factory.getKeySpec((SecretKey) key, KeyInfo.class);
            return info.isUserAuthenticationRequired();
        } catch (Exception e) {
            return false;
        }
    }

    SecretKey getSecretKey() throws Exception {
        ensureSymmetricKeyAtAlias();
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
        ks.load(null);
        Key key = ks.getKey(keyAlias, null);
        if (!(key instanceof SecretKey)) {
            throw new IllegalStateException("Keystore alias does not hold a SecretKey");
        }
        return (SecretKey) key;
    }

    @Override
    public boolean usesKeystoreAesKey() {
        return true;
    }

    @Override
    public SecretKey getKeystoreAesKey() throws Exception {
        return getSecretKey();
    }

    /**
     * Builds an ENCRYPT Cipher for value encryption after CryptoObject unlock.
     */
    Cipher createValueEncryptCipher() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey());
        return cipher;
    }

    /**
     * Builds a DECRYPT Cipher for a value IV after CryptoObject unlock.
     */
    Cipher createValueDecryptCipher(byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), new GCMParameterSpec(128, iv));
        return cipher;
    }

    @Override
    public boolean isInvalidatedByBiometricEnrollment() {
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
                return false;
            }
            KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
            ks.load(null);
            Key key = ks.getKey(keyAlias, null);
            if (!(key instanceof SecretKey)) {
                return false;
            }
            SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), KEYSTORE_PROVIDER_ANDROID);
            KeyInfo info = (KeyInfo) factory.getKeySpec((SecretKey) key, KeyInfo.class);
            return info.isInvalidatedByBiometricEnrollment();
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean isPermanentlyInvalidated() {
        try {
            KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
            ks.load(null);
            Key key = ks.getKey(keyAlias, null);
            SharedPreferences preferences = context.getSharedPreferences(
                    config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
            boolean hasWrappedKey = StorageCipherImplementationAES23.hasApplicationKey(preferences);
            if (key == null) {
                return hasWrappedKey;
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return false;
        } catch (UserNotAuthenticatedException e) {
            return false;
        } catch (KeyPermanentlyInvalidatedException e) {
            return true;
        } catch (java.security.UnrecoverableKeyException e) {
            return true;
        } catch (Exception e) {
            Log.w(TAG, "Could not probe wrapping key", e);
            return false;
        }
    }

    @Override
    public Cipher getCipher(Context context) throws Exception {
        ensureSymmetricKeyAtAlias();
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
        ks.load(null);
        Key key = ks.getKey(keyAlias, null);
        SharedPreferences preferences = context.getSharedPreferences(
                config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        if (StorageCipherImplementationAES23.hasApplicationKey(preferences)) {
            return getLegacyWrapCipher(context, key);
        }
        // Keystore-direct: unlock Cipher for CryptoObject (does not persist a wrap IV).
        return createUnlockCipher(key);
    }

    /**
     * Builds an ENCRYPT Cipher for BiometricPrompt CryptoObject unlock.
     * Used when values are encrypted directly by the Keystore key.
     */
    Cipher createUnlockCipher(Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher;
    }

    public Cipher getEncryptionCipher(Context context, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        return getLegacyWrapCipher(context, key);
    }

    private Cipher getLegacyWrapCipher(Context context, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SharedPreferences preferences = context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE);
        String ivBase64 = preferences.getString(SHARED_PREFERENCES_KEY, null);

        if (ivBase64 != null && StorageCipherImplementationAES23.hasApplicationKey(preferences)) {
            byte[] iv = Base64.decode(ivBase64, Base64.DEFAULT);
            GCMParameterSpec spec = new GCMParameterSpec(IV_SIZE * Byte.SIZE, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
        } else {
            // IV missing, or IV exists but app key doesn't (stale from a failed/cancelled auth).
            // Start fresh with a new ENCRYPT cipher.
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] iv = cipher.getIV();
            SharedPreferences.Editor editor = preferences.edit();
            editor.putString(SHARED_PREFERENCES_KEY, Base64.encodeToString(iv, Base64.DEFAULT));
            editor.apply();
        }

        return cipher;
    }

    /**
     * Checks if StrongBox is available on the device.
     * StrongBox is a hardware security module that provides additional protection for cryptographic keys.
     */
    protected boolean isStrongBoxAvailable() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return false;
        }
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
    }

    /**
     * Checks if device has PIN/biometric security enabled.
     * This is used to determine if we should require user authentication for the key.
     */
    protected boolean isDeviceSecure() {
        android.app.KeyguardManager keyguardManager =
            (android.app.KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        return keyguardManager != null && keyguardManager.isDeviceSecure();
    }

    public void generateSymmetricKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER_ANDROID);

        // Check if device has security (PIN/biometric) configured
        boolean deviceHasSecurity = isDeviceSecure();
        boolean enforceBiometrics = config.getEnforceBiometrics();

        // ENFORCEMENT MODE: Fail if enforcement enabled but no device security
        if (enforceBiometrics && !deviceHasSecurity) {
            throw new Exception("BIOMETRIC_UNAVAILABLE: Biometric enforcement enabled but device has no PIN, pattern, password, or biometric enrolled. Cannot generate secure key.");
        }

        // GRACEFUL DEGRADATION MODE: Log warning if no device security
        if (!deviceHasSecurity) {
            Log.w(TAG, "Device has no PIN/biometric security. Generating key without user authentication requirement (enforceBiometrics=false).");
        }

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(KEY_SIZE);

        // Set authentication requirement based on device security
        if (deviceHasSecurity) {
            configureUserAuthentication(builder);
        } else {
            // Explicitly set to false for clarity (default behavior)
            builder.setUserAuthenticationRequired(false);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(true);

            // Only enable StrongBox if it's available
            if (isStrongBoxAvailable()) {
                builder.setIsStrongBoxBacked(true);
                Log.d(TAG, "StrongBox is available and enabled for biometric key");
            } else {
                Log.w(TAG, "StrongBox requested but not available on this device. Using standard TEE.");
            }
        }

        try {
            keyGenerator.init(builder.build());
            keyGenerator.generateKey();
        } catch (Exception e) {
            // If key generation fails with StrongBox, retry without it
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && isStrongBoxAvailable()) {
                Log.w(TAG, " Key generation failed with StrongBox. Retrying without StrongBox.", e);

                builder = new KeyGenParameterSpec.Builder(
                        keyAlias,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(KEY_SIZE)
                        .setUnlockedDeviceRequired(true);

                if (deviceHasSecurity) {
                    configureUserAuthentication(builder);
                }

                keyGenerator.init(builder.build());
                keyGenerator.generateKey();
                Log.d(TAG, "Key generation succeeded without StrongBox");
            } else {
                throw e;
            }
        }
    }

    /**
     * CryptoObject unlocks the Keystore key; a short validity window then allows
     * multiple value encrypt/decrypt inits (e.g. readAll) without re-prompting.
     * The Keystore key remains non-extractable (no software app key in the heap).
     */
    private void configureUserAuthentication(KeyGenParameterSpec.Builder builder) {
        builder.setUserAuthenticationRequired(true);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            int authTypes = config.isStrongBiometricOnly()
                    ? AUTH_BIOMETRIC_STRONG
                    : AUTH_DEVICE_CREDENTIAL | AUTH_BIOMETRIC_STRONG;
            builder.setUserAuthenticationParameters(AUTH_VALIDITY_SECONDS, authTypes);
        } else {
            configureLegacyAuth(builder);
        }
        // Match iOS biometryCurrentSet: enrollment changes invalidate the wrapping key.
        builder.setInvalidatedByBiometricEnrollment(true);
    }

    /**
     * Separate function due to build procedure still marking this as deprecated.
     */
    @SuppressWarnings({"deprecation", "RedundantSuppression"})
    private void configureLegacyAuth(KeyGenParameterSpec.Builder builder) {
        builder.setUserAuthenticationValidityDurationSeconds(AUTH_VALIDITY_SECONDS);
    }


}
