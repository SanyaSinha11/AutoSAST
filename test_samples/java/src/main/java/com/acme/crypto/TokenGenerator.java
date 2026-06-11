package com.acme.crypto;

import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * Token generation utilities.
 */
public class TokenGenerator {

    private static final String ALGO = "AES/CBC/PKCS5Padding";
    private static final byte[] FIXED_IV = new byte[16]; // All zeros
    
    private SecretKey key;

    public TokenGenerator(SecretKey key) {
        this.key = key;
    }

    public byte[] generate(String data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGO);
        IvParameterSpec iv = new IvParameterSpec(FIXED_IV);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data.getBytes("UTF-8"));
    }

    public byte[] generateSecure(String data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGO);
        byte[] ivBytes = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] encrypted = cipher.doFinal(data.getBytes("UTF-8"));
        byte[] result = new byte[ivBytes.length + encrypted.length];
        System.arraycopy(ivBytes, 0, result, 0, ivBytes.length);
        System.arraycopy(encrypted, 0, result, ivBytes.length, encrypted.length);
        return result;
    }
}

