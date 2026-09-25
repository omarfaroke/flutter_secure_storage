package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig;

import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

public class StorageCipherImplementationAES23 implements StorageCipher {
    private static final int keySize = 32;
    private static final int defaultIvSize = 12;
    private static final int AUTHENTICATION_TAG_SIZE = 128;
    private static final String KEY_ALGORITHM = "AES";
    private static final String KEYSTORE_IV_NAME = "BVGhpcyBpcyB0aGUga2V5IGZvciBhIHNlY3VyZSBzdG9yYWdlIEFFUyBLZXkK";
    public static final String APP_KEY_PREF = KEYSTORE_IV_NAME;
    private final String keyStoragePrefsName;
    private final Cipher cipher;
    private final SecureRandom secureRandom;
    private SecretKey secretKey;

    public StorageCipherImplementationAES23(Context context, KeyCipher ignoredKeyCipher, Cipher cipher, FlutterSecureStorageConfig config) throws Exception {
        keyStoragePrefsName = config.getEffectiveKeyStoragePrefsName();
        secureRandom = new SecureRandom();
        this.cipher = getCipher();
        this.secretKey = loadOrGenerateApplicationKey(context, cipher);
    }

    public static boolean hasApplicationKey(SharedPreferences preferences) {
        return preferences.contains(KEYSTORE_IV_NAME);
    }

    private SecretKey loadOrGenerateApplicationKey(Context context, Cipher biometricCipher) throws Exception {
        final Cipher cipher = (biometricCipher != null) ? biometricCipher : getCipher();
        assert (cipher != null);
        SharedPreferences preferences = context.getSharedPreferences(keyStoragePrefsName, Context.MODE_PRIVATE);
        String encryptedAppKeyBase64 = preferences.getString(KEYSTORE_IV_NAME, null);

        if (encryptedAppKeyBase64 != null) {
            // Decrypt existing key - may throw BadPaddingException, IllegalBlockSizeException if algorithm changed
            byte[] encryptedAppKey = Base64.decode(encryptedAppKeyBase64, Base64.DEFAULT);
            byte[] appKey = cipher.doFinal(encryptedAppKey);
            try {
                return new SecretKeySpec(appKey, KEY_ALGORITHM);
            } finally {
                Arrays.fill(appKey, (byte) 0);
            }
        }

        // No stored key - generate new one (first initialization)
        byte[] appKey = generateIV(keySize);
        SecretKey secretKey = new SecretKeySpec(appKey, KEY_ALGORITHM);
        byte[] newEncryptedAppKey = cipher.doFinal(appKey);
        Arrays.fill(appKey, (byte) 0);

        SharedPreferences.Editor editor = preferences.edit();
        editor.putString(KEYSTORE_IV_NAME, Base64.encodeToString(newEncryptedAppKey, Base64.DEFAULT));
        editor.apply();

        return secretKey;
    }

    @Override
    public void deleteKey(Context context) {
        SharedPreferences preferences = context.getSharedPreferences(keyStoragePrefsName, Context.MODE_PRIVATE);
        preferences.edit().remove(KEYSTORE_IV_NAME).apply();
        destroy();
    }

    @Override
    public void destroy() {
        if (secretKey instanceof Destroyable) {
            try {
                ((Destroyable) secretKey).destroy();
            } catch (DestroyFailedException ignored) {
                byte[] encoded = secretKey.getEncoded();
                if (encoded != null) {
                    Arrays.fill(encoded, (byte) 0);
                }
            }
        }
        secretKey = null;
    }

    public byte[] copyApplicationKey() {
        if (secretKey == null) {
            throw new IllegalStateException("Cipher has been destroyed");
        }
        byte[] encoded = secretKey.getEncoded();
        if (encoded == null) {
            throw new IllegalStateException("Application key cannot be exported");
        }
        return encoded;
    }

    public static void clearWrappedApplicationKey(Context context, FlutterSecureStorageConfig config) {
        context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE)
                .edit()
                .remove(APP_KEY_PREF)
                .apply();
    }

    public static void storeWrappedApplicationKey(Context context, FlutterSecureStorageConfig config,
                                           Cipher encryptCipher, byte[] appKey) throws Exception {
        byte[] encrypted = encryptCipher.doFinal(appKey);
        context.getSharedPreferences(config.getEffectiveKeyStoragePrefsName(), Context.MODE_PRIVATE)
                .edit()
                .putString(APP_KEY_PREF, Base64.encodeToString(encrypted, Base64.DEFAULT))
                .apply();
    }

    protected Cipher getCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    @Override
    public byte[] encrypt(byte[] input) throws Exception {
        if (secretKey == null) {
            throw new IllegalStateException("Cipher has been destroyed");
        }
        byte[] iv = generateIV(defaultIvSize);

        GCMParameterSpec spec = new GCMParameterSpec(AUTHENTICATION_TAG_SIZE, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        byte[] payload = cipher.doFinal(input);
        try {
            byte[] combined = new byte[iv.length + payload.length];

            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(payload, 0, combined, iv.length, payload.length);

            return combined;
        } finally {
            Arrays.fill(payload, (byte) 0);
        }
    }

    @Override
    public byte[] decrypt(byte[] input) throws Exception {
        if (secretKey == null) {
            throw new IllegalStateException("Cipher has been destroyed");
        }
        byte[] iv = new byte[defaultIvSize];
        System.arraycopy(input, 0, iv, 0, iv.length);
        int payloadSize = input.length - defaultIvSize;
        byte[] payload = new byte[payloadSize];
        System.arraycopy(input, iv.length, payload, 0, payloadSize);

        try {
            GCMParameterSpec spec = new GCMParameterSpec(AUTHENTICATION_TAG_SIZE, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

            return cipher.doFinal(payload);
        } finally {
            Arrays.fill(payload, (byte) 0);
        }
    }

    public byte[] generateIV(int size) {
        byte[] iv = new byte[size];
        secureRandom.nextBytes(iv);
        return iv;
    }

}
