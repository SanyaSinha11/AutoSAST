package com.acme.storage;

import java.io.*;
import java.net.*;
import java.nio.file.*;

/**
 * Asset storage management.
 */
public class AssetManager {

    private static final String CDN = "https://cdn.acme.com";

    // TP: SSRF - user controls URL
    public byte[] fetchRemote(String location) throws Exception {
        URL url = new URL(location);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        InputStream is = conn.getInputStream();
        byte[] buf = new byte[4096];
        int len;
        while ((len = is.read(buf)) != -1) {
            baos.write(buf, 0, len);
        }
        return baos.toByteArray();
    }

    // FP: Only allows CDN URLs
    public byte[] fetchFromCdn(String assetId) throws Exception {
        if (assetId == null || !assetId.matches("^[a-zA-Z0-9_-]+$")) {
            throw new IllegalArgumentException("Invalid asset ID");
        }
        
        String urlStr = CDN + "/assets/" + assetId;
        URL url = new URL(urlStr);
        
        if (!url.getHost().equals("cdn.acme.com")) {
            throw new SecurityException("Invalid host");
        }
        
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        InputStream is = conn.getInputStream();
        byte[] buf = new byte[4096];
        int len;
        while ((len = is.read(buf)) != -1) {
            baos.write(buf, 0, len);
        }
        return baos.toByteArray();
    }
}

