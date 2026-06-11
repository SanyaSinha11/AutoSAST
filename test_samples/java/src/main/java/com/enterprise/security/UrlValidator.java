package com.enterprise.security;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class UrlValidator {

    private static final List<String> ALLOWED_HOSTS = Arrays.asList(
        "api.company.com", "cdn.company.com", "assets.company.com",
        "images.company.com", "static.company.com"
    );

    private static final List<String> ALLOWED_SCHEMES = Arrays.asList("https");

    private static final Pattern PRIVATE_IP = Pattern.compile(
        "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.|0\\.|169\\.254\\.|localhost)"
    );

    public boolean isAllowedHost(String urlString) {
        try {
            URL url = new URL(urlString);
            return ALLOWED_HOSTS.contains(url.getHost().toLowerCase());
        } catch (MalformedURLException e) {
            return false;
        }
    }

    public boolean isSecureScheme(String urlString) {
        try {
            URL url = new URL(urlString);
            return ALLOWED_SCHEMES.contains(url.getProtocol().toLowerCase());
        } catch (MalformedURLException e) {
            return false;
        }
    }

    public boolean isPrivateIp(String host) {
        return PRIVATE_IP.matcher(host).find();
    }

    public String validateAndNormalize(String urlString) throws SecurityException {
        if (urlString == null || urlString.isEmpty()) {
            throw new SecurityException("URL cannot be empty");
        }

        try {
            URL url = new URL(urlString);
            
            if (!isSecureScheme(urlString)) {
                throw new SecurityException("Only HTTPS URLs are allowed");
            }

            String host = url.getHost().toLowerCase();
            if (isPrivateIp(host)) {
                throw new SecurityException("Private IP addresses are not allowed");
            }

            if (!ALLOWED_HOSTS.contains(host)) {
                throw new SecurityException("Host not in allowlist: " + host);
            }

            return url.toString();
        } catch (MalformedURLException e) {
            throw new SecurityException("Invalid URL format: " + e.getMessage());
        }
    }
}

