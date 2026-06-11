package com.example.service;

import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * Crypto Service for encryption and hashing operations.
 */
public class CryptoService {

    public String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(digest);
    }

    public byte[] encryptData(byte[] data, byte[] key)
            throws GeneralSecurityException {
        SecretKeySpec keySpec = new SecretKeySpec(Arrays.copyOf(key, 8), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }
}

