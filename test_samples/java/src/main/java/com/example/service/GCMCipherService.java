package com.example.service;

import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * GCM Cipher Service - Demonstrates SECURE IV handling.
 * This is a FALSE POSITIVE case - the IV is generated fresh for each encryption.
 */
public class GCMCipherService {

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private final SecureRandom secureRandom;
    private final SecretKey secretKey;

    public GCMCipherService(SecretKey key) {
        this.secretKey = key;
        this.secureRandom = new SecureRandom();
    }

    /**
     * Encrypts data using AES-GCM with a fresh IV for each call.
     * The IV is prepended to the ciphertext for decryption.
     */
    public byte[] encrypt(byte[] plaintext) throws GeneralSecurityException {
        // Generate a fresh IV for EACH encryption - this is SECURE
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);  // Fresh random IV every time

        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        byte[] ciphertext = cipher.doFinal(plaintext);

        // Prepend IV to ciphertext for transmission
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);

        return result;
    }

    /**
     * Decrypts data encrypted with the encrypt method.
     */
    public byte[] decrypt(byte[] ciphertextWithIv) throws GeneralSecurityException {
        // Extract IV from the beginning
        byte[] iv = Arrays.copyOfRange(ciphertextWithIv, 0, GCM_IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(ciphertextWithIv, GCM_IV_LENGTH, ciphertextWithIv.length);

        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        return cipher.doFinal(ciphertext);
    }

    /**
     * Helper method to generate a secure AES key.
     */
    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, new SecureRandom());
        return keyGen.generateKey();
    }
}

