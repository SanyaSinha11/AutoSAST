package com.acme.auth;

import java.util.*;
import java.security.SecureRandom;

/**
 * Session management.
 */
public class SessionManager {

    private Map<String, Object> sessions = new HashMap<>();
    private Random insecureRandom = new Random();
    private SecureRandom secureRandom = new SecureRandom();

    // TP: Uses predictable random for session ID
    public String createSessionWeak() {
        byte[] bytes = new byte[32];
        insecureRandom.nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        String sessionId = sb.toString();
        sessions.put(sessionId, new HashMap<>());
        return sessionId;
    }

    // FP: Uses SecureRandom
    public String createSessionStrong() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        String sessionId = sb.toString();
        sessions.put(sessionId, new HashMap<>());
        return sessionId;
    }

    public Object getSession(String id) {
        return sessions.get(id);
    }
}

