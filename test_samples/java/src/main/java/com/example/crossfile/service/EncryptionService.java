package com.example.crossfile.service;

import com.example.crossfile.security.CryptoConfig;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

/**
 * Encryption Service - Handles data encryption.
 * 
 * TRUE POSITIVE: GCM IV Reuse Vulnerability
 * 
 * This service uses a STATIC IV from CryptoConfig for every encryption.
 * The IV should be randomly generated for each encryption operation.
 * 
 * Cross-file analysis needed to detect:
 * - CryptoConfig.STATIC_IV is a constant (not randomly generated)
 * - The same IV is used for every call to encrypt()
 */
public class EncryptionService {

    private final SecretKey secretKey;

    public EncryptionService() {
        this.secretKey = CryptoConfig.getSecretKey();
    }

    /**
     * Encrypt data using AES-GCM.
     * 
     * VULNERABLE: Uses static IV from CryptoConfig.STATIC_IV
     * The IV is defined in CryptoConfig.java and never changes.
     * 
     * Cross-file context should reveal:
     * 1. CryptoConfig.STATIC_IV is a static final byte array
     * 2. It's initialized once and never regenerated
     * 3. Same IV is used for all encryption operations
     */
    public byte[] encrypt(byte[] plaintext) throws GeneralSecurityException {
        // VULNERABILITY: Static IV from another file
        GCMParameterSpec parameterSpec = new GCMParameterSpec(
            CryptoConfig.GCM_TAG_LENGTH, 
            CryptoConfig.STATIC_IV  // <-- This is the vulnerability!
        );
        
        Cipher cipher = Cipher.getInstance(CryptoConfig.ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        return cipher.doFinal(plaintext);
    }

    public byte[] decrypt(byte[] ciphertext) throws GeneralSecurityException {
        GCMParameterSpec parameterSpec = new GCMParameterSpec(
            CryptoConfig.GCM_TAG_LENGTH, 
            CryptoConfig.STATIC_IV
        );
        
        Cipher cipher = Cipher.getInstance(CryptoConfig.ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        
        return cipher.doFinal(ciphertext);
    }
}

