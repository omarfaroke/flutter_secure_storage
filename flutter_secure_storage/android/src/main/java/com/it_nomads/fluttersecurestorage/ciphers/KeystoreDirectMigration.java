package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.SharedPreferences;
import android.util.Base64;

import java.util.Arrays;
import java.util.Map;

/**
 * One-time re-encryption from legacy software app-key ciphertext to Keystore-direct GCM.
 */
public final class KeystoreDirectMigration {

    private KeystoreDirectMigration() {
    }

    /**
     * Decrypts all data-prefix entries with {@code legacyCipher}, re-encrypts with
     * {@code directCipher}, then removes legacy APP_KEY and wrap-IV prefs.
     * On failure before the data commit, prefs are unchanged.
     */
    public static void migrate(SharedPreferences dataPrefs,
                        String keyPrefix,
                        StorageCipher legacyCipher,
                        StorageCipher directCipher,
                        SharedPreferences keyPrefs) throws Exception {
        SharedPreferences.Editor editor = dataPrefs.edit();
        for (Map.Entry<String, ?> entry : dataPrefs.getAll().entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (!(value instanceof String) || !key.contains(keyPrefix)) {
                continue;
            }
            byte[] encrypted = Base64.decode((String) value, 0);
            byte[] plain = legacyCipher.decrypt(encrypted);
            try {
                byte[] reencrypted = directCipher.encrypt(plain);
                editor.putString(key, Base64.encodeToString(reencrypted, 0));
            } finally {
                Arrays.fill(plain, (byte) 0);
            }
        }
        if (!editor.commit()) {
            throw new Exception("Failed to commit Keystore-direct migration");
        }

        if (!keyPrefs.edit()
                .remove(StorageCipherImplementationAES23.APP_KEY_PREF)
                .remove("KeyStoreIV1")
                .commit()) {
            throw new Exception("Failed to clear legacy app-key prefs after migration");
        }
    }
}
