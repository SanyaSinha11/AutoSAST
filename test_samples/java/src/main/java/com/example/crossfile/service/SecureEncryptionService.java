package com.example.crossfile.service;

import com.example.crossfile.security.SecureIVGenerator;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

/**
 * Secure Encryption Service - Implements proper AES-GCM encryption.
 * 
 * FALSE POSITIVE for IV reuse: This class uses SecureIVGenerator
 * which generates a fresh random IV for each encryption operation.
 * 
 * Cross-file analysis needed to detect:
 * - ivGenerator.generateIV() creates a NEW random IV each time
 * - SecureIVGenerator uses SecureRandom internally
 * - The IV is prepended to ciphertext for decryption
 */
public class SecureEncryptionService {

    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    
    private final SecretKey secretKey;
    private final SecureIVGenerator ivGenerator;

    public SecureEncryptionService(SecretKey key) {
        this.secretKey = key;
        this.ivGenerator = new SecureIVGenerator();
    }

    /**
     * Encrypt data using AES-GCM with a fresh random IV.
     * 
     * SECURE: Uses SecureIVGenerator to generate a new IV for each encryption.
     * The IV is prepended to the ciphertext so it can be used for decryption.
     * 
     * Cross-file context should reveal:
     * 1. ivGenerator.generateIV() uses SecureRandom
     * 2. A NEW IV is generated for each call
     * 3. This is NOT IV reuse - it's secure
     */
    public byte[] encrypt(byte[] plaintext) throws GeneralSecurityException {
        // SECURE: Generate fresh IV for EACH encryption
        byte[] iv = ivGenerator.generateIV();
        
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        byte[] ciphertext = cipher.doFinal(plaintext);
        
        // Prepend IV to ciphertext
        byte[] result = new byte[GCM_IV_LENGTH + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, GCM_IV_LENGTH);
        System.arraycopy(ciphertext, 0, result, GCM_IV_LENGTH, ciphertext.length);
        
        return result;
    }

    public byte[] decrypt(byte[] ciphertextWithIv) throws GeneralSecurityException {
        // Extract IV from beginning
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(ciphertextWithIv, 0, iv, 0, GCM_IV_LENGTH);
        
        byte[] ciphertext = new byte[ciphertextWithIv.length - GCM_IV_LENGTH];
        System.arraycopy(ciphertextWithIv, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);
        
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        
        return cipher.doFinal(ciphertext);
    }
}

