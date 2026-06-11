package com.acme.crypto;

import java.security.*;
import java.nio.charset.StandardCharsets;
import org.mindrot.jbcrypt.BCrypt;

/**
 * Hashing utilities.
 */
public class HashUtil {

    // TP: MD5 for password hashing is insecure
    public static String hashLegacy(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // FP: BCrypt is appropriate for password hashing
    public static String hashModern(String input) {
        return BCrypt.hashpw(input, BCrypt.gensalt(12));
    }

    // FP: SHA-256 for data integrity (not passwords) is fine
    public static String checksum(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

