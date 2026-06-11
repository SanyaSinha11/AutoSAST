package com.example.crossfile.security;

import java.security.SecureRandom;

/**
 * Secure IV Generator - Generates cryptographically secure random IVs.
 * 
 * This class provides secure IV generation for use in AES-GCM encryption.
 * Each call to generateIV() produces a new random IV, ensuring that
 * no two encryption operations use the same IV.
 */
public class SecureIVGenerator {

    private static final int GCM_IV_LENGTH = 12; // 96 bits for GCM
    private final SecureRandom secureRandom;

    public SecureIVGenerator() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * Generate a fresh, cryptographically secure random IV.
     * 
     * This method generates a NEW random IV for each call.
     * The IV is suitable for use with AES-GCM encryption.
     * 
     * @return A new 12-byte random IV
     */
    public byte[] generateIV() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }

    /**
     * Generate IV with custom length.
     * 
     * @param length The desired IV length in bytes
     * @return A new random IV of the specified length
     */
    public byte[] generateIV(int length) {
        byte[] iv = new byte[length];
        secureRandom.nextBytes(iv);
        return iv;
    }
}

