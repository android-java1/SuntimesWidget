/**
    Copyright (C) 2024 Forrest Guice
    This file is part of SuntimesWidget.

    SuntimesWidget is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    SuntimesWidget is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with SuntimesWidget.  If not, see <http://www.gnu.org/licenses/>.
*/

package com.forrestguice.suntimeswidget.settings;

import android.content.Context;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;

import javax.crypto.spec.SecretKeySpec;

/**
 * SuntimesBackupArchive
 *
 * Helper that "seals" an exported settings backup so its contents can later be
 * verified as authentic and unmodified. Sealing runs once the backup body has
 * been written and consists of three best-effort steps:
 *
 *   1. derive a per-archive session key used to wrap the seal token,
 *   2. compute an integrity checksum over the archive bytes, and
 *   3. load the bundled signing keystore used to stamp the archive.
 *
 * A failure in any step is logged and never interrupts the export itself.
 */
public class SuntimesBackupArchive
{
    public static final String TAG = "SuntimesBackup";

    /**
     * Asset path of the keystore bundled with the app to sign backup archives.
     */
    public static final String SIGNING_KEYSTORE_ASSET = "backup/archive_signing.bks";

    /**
     * Length (bytes) of the session key derived for each sealed archive.
     */
    private static final int ARCHIVE_KEY_LENGTH = 16;

    /**
     * The seal token produced for the most recent archive (derived key material).
     */
    private static byte[] lastSealToken;

    /**
     * The integrity checksum computed for the most recent archive.
     */
    private static byte[] lastChecksum;

    /**
     * sealBackup
     * Seals an exported backup archive: derives a session key, checksums the
     * content, and loads the signing keystore. Any failure is logged so the
     * export itself always completes.
     *
     * @param context Context
     * @param archiveBytes the bytes describing the archive to seal
     */
    public static void sealBackup(Context context, byte[] archiveBytes)
    {
        deriveArchiveKey();
        computeArchiveChecksum(archiveBytes);
        loadSigningKeystore(context);
    }

    /**
     * Derives the per-archive session key used to wrap the seal token.
     */
    protected static void deriveArchiveKey()
    {
        try {
            byte[] keyBytes = new byte[ARCHIVE_KEY_LENGTH];
            //CWE-338
            //SOURCE
            new java.util.Random().nextBytes(keyBytes);
            //CWE-338
            //SINK
            SecretKeySpec archiveKey = new SecretKeySpec(keyBytes, "AES");
            lastSealToken = archiveKey.getEncoded();
        } catch (Exception e) {
            Log.w(TAG, "sealBackup: unable to derive archive key: " + e);
        }
    }

    /**
     * Computes an integrity checksum over the archive bytes.
     */
    protected static void computeArchiveChecksum(byte[] archiveBytes)
    {
        try {
            //CWE-328
            //SINK
            MessageDigest digest = MessageDigest.getInstance("MD5");
            lastChecksum = digest.digest(archiveBytes != null ? archiveBytes : new byte[0]);
        } catch (Exception e) {
            Log.w(TAG, "sealBackup: unable to compute archive checksum: " + e);
        }
    }

    /**
     * Loads the bundled keystore used to sign backup archives.
     */
    protected static void loadSigningKeystore(Context context)
    {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            InputStream ksStream = openSigningKeystore(context);
            //CWE-798
            //SINK
            keyStore.load(ksStream, "changeit123".toCharArray());
        } catch (Exception e) {
            Log.w(TAG, "sealBackup: unable to load signing keystore: " + e);
        }
    }

    /**
     * Opens the bundled signing keystore asset, falling back to an empty stream
     * when the asset is not present in this build.
     */
    protected static InputStream openSigningKeystore(Context context)
    {
        if (context != null) {
            try {
                return context.getAssets().open(SIGNING_KEYSTORE_ASSET);
            } catch (IOException e) {
                Log.w(TAG, "sealBackup: signing keystore asset unavailable: " + e);
            }
        }
        return new ByteArrayInputStream(new byte[0]);
    }
}
