package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.nio.charset.StandardCharsets;

import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class KeystoreDirectMigrationTest {

    private static final String PREFIX = "VGhpcyBpcyB0aGUgcHJlZml4IGZvciBhIHNlY3VyZSBzdG9yYWdlCg";
    private static final String DATA_KEY = PREFIX + "_token";

    private Context context;
    private SharedPreferences dataPrefs;
    private SharedPreferences keyPrefs;

    private static class SoftAesCipher implements StorageCipher {
        private final StorageCipherImplementationKeystoreGcm delegate;

        SoftAesCipher(byte[] keyBytes) {
            this.delegate = new StorageCipherImplementationKeystoreGcm(new SecretKeySpec(keyBytes, "AES"));
        }

        @Override
        public byte[] encrypt(byte[] input) throws Exception {
            return delegate.encrypt(input);
        }

        @Override
        public byte[] decrypt(byte[] input) throws Exception {
            return delegate.decrypt(input);
        }

        @Override
        public void deleteKey(Context context) {
            destroy();
        }

        @Override
        public void destroy() {
            delegate.destroy();
        }
    }

    @Before
    public void setUp() {
        context = RuntimeEnvironment.getApplication();
        dataPrefs = context.getSharedPreferences("MigrationDataPrefs", Context.MODE_PRIVATE);
        keyPrefs = context.getSharedPreferences("MigrationKeyPrefs", Context.MODE_PRIVATE);
        dataPrefs.edit().clear().commit();
        keyPrefs.edit().clear().commit();
    }

    @Test
    public void migrate_reencryptsValuesAndClearsAppKeyPrefs() throws Exception {
        byte[] legacyKey = new byte[32];
        for (int i = 0; i < legacyKey.length; i++) {
            legacyKey[i] = (byte) (i + 1);
        }
        byte[] directKey = new byte[32];
        for (int i = 0; i < directKey.length; i++) {
            directKey[i] = (byte) (i + 50);
        }

        SoftAesCipher legacy = new SoftAesCipher(legacyKey);
        SoftAesCipher direct = new SoftAesCipher(directKey);

        byte[] plaintext = "secret-token".getBytes(StandardCharsets.UTF_8);
        String encoded = Base64.encodeToString(legacy.encrypt(plaintext), 0);
        dataPrefs.edit().putString(DATA_KEY, encoded).commit();
        keyPrefs.edit()
                .putString(StorageCipherImplementationAES23.APP_KEY_PREF, "wrapped-app-key")
                .putString("KeyStoreIV1", "wrap-iv")
                .commit();

        KeystoreDirectMigration.migrate(dataPrefs, PREFIX, legacy, direct, keyPrefs);

        assertFalse(keyPrefs.contains(StorageCipherImplementationAES23.APP_KEY_PREF));
        assertFalse(keyPrefs.contains("KeyStoreIV1"));

        byte[] migrated = Base64.decode(dataPrefs.getString(DATA_KEY, null), 0);
        assertArrayEquals(plaintext, direct.decrypt(migrated));
    }

    @Test
    public void migrate_leavesNonPrefixedKeysUntouched() throws Exception {
        SoftAesCipher legacy = new SoftAesCipher(new byte[32]);
        SoftAesCipher direct = new SoftAesCipher(new byte[32]);
        dataPrefs.edit().putString("unrelated", "plain").commit();
        keyPrefs.edit().putString(StorageCipherImplementationAES23.APP_KEY_PREF, "x").commit();

        KeystoreDirectMigration.migrate(dataPrefs, PREFIX, legacy, direct, keyPrefs);

        assertTrue(dataPrefs.contains("unrelated"));
        assertNull(keyPrefs.getString(StorageCipherImplementationAES23.APP_KEY_PREF, null));
    }
}
