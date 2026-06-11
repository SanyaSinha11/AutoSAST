package com.example.crossfile.security;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Crypto Configuration - Contains encryption constants.
 * 
 * VULNERABILITY: This file defines a STATIC IV that is reused
 * across all encryption operations in EncryptionService.
 * 
 * This is a TRUE POSITIVE for IV reuse vulnerability.
 */
public class CryptoConfig {

    // VULNERABLE: Static IV - reused for every encryption!
    // GCM mode requires a unique IV/nonce for each encryption with the same key.
    // Reusing IVs with GCM allows attackers to:
    // 1. XOR ciphertexts to recover plaintext
    // 2. Forge authentication tags
    public static final byte[] STATIC_IV = new byte[] {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B
    };

    public static final int GCM_TAG_LENGTH = 128;
    public static final String ALGORITHM = "AES/GCM/NoPadding";

    // Hardcoded key (also a vulnerability, but separate issue)
    private static final byte[] KEY_BYTES = new byte[] {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    public static SecretKey getSecretKey() {
        return new SecretKeySpec(KEY_BYTES, "AES");
    }
}

