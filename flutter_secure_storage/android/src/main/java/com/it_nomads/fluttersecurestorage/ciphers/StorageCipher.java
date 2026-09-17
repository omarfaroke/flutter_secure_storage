package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;

public interface StorageCipher {
    byte[] encrypt(byte[] input) throws Exception;

    byte[] decrypt(byte[] input) throws Exception;

    void deleteKey(Context context) throws Exception;

    /** Clears in-memory key material. Safe to call more than once. */
    default void destroy() {}
}
