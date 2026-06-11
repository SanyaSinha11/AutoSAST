package com.example.service;

import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * VULNERABLE GCM Cipher Service - Uses static IV (INSECURE).
 * This is a TRUE POSITIVE case - the IV is reused across encryptions.
 */
public class VulnerableGCMService {

    private static final int GCM_TAG_LENGTH = 128;
    // VULNERABILITY: Static IV - reused for every encryption!
    private static final byte[] STATIC_IV = new byte[] {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B
    };
    private final SecretKey secretKey;

    public VulnerableGCMService(SecretKey key) {
        this.secretKey = key;
    }

    /**
     * VULNERABLE: Uses static IV for all encryptions.
     * This allows attackers to recover plaintext through XOR attacks.
     */
    public byte[] encrypt(byte[] plaintext) throws GeneralSecurityException {
        // VULNERABILITY: Same IV used every time!
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, STATIC_IV);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        return cipher.doFinal(plaintext);
    }

    public byte[] decrypt(byte[] ciphertext) throws GeneralSecurityException {
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, STATIC_IV);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        return cipher.doFinal(ciphertext);
    }
}

