package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;

import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Encrypts values directly with a non-extractable Android Keystore AES key.
 * No software app key is ever materialised in the Java heap.
 */
public class StorageCipherImplementationKeystoreGcm implements StorageCipher {
    private static final int DEFAULT_IV_SIZE = 12;
    private static final int AUTHENTICATION_TAG_SIZE = 128;

    private final SecureRandom secureRandom = new SecureRandom();
    private SecretKey secretKey;

    public StorageCipherImplementationKeystoreGcm(SecretKey secretKey) {
        if (secretKey == null) {
            throw new IllegalArgumentException("Keystore secret key is required");
        }
        this.secretKey = secretKey;
    }

    @Override
    public byte[] encrypt(byte[] input) throws Exception {
        if (secretKey == null) {
            throw new IllegalStateException("Cipher has been destroyed");
        }
        byte[] iv = generateIv(DEFAULT_IV_SIZE);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(AUTHENTICATION_TAG_SIZE, iv));
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
        byte[] iv = new byte[DEFAULT_IV_SIZE];
        System.arraycopy(input, 0, iv, 0, iv.length);
        int payloadSize = input.length - DEFAULT_IV_SIZE;
        byte[] payload = new byte[payloadSize];
        System.arraycopy(input, iv.length, payload, 0, payloadSize);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(AUTHENTICATION_TAG_SIZE, iv));
            return cipher.doFinal(payload);
        } finally {
            Arrays.fill(payload, (byte) 0);
        }
    }

    @Override
    public void deleteKey(Context context) {
        destroy();
    }

    @Override
    public void destroy() {
        secretKey = null;
    }

    private byte[] generateIv(int size) {
        byte[] iv = new byte[size];
        secureRandom.nextBytes(iv);
        return iv;
    }
}
