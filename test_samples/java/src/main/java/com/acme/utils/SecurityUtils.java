package com.acme.utils;

/**
 * Security utilities for input sanitization.
 */
public class SecurityUtils {
    
    /**
     * Sanitizes input for safe use in SQL queries by removing dangerous characters.
     * Uses an allowlist approach - only alphanumeric characters are allowed.
     */
    public static String sanitizeForSql(String input) {
        if (input == null) {
            return "";
        }
        // Only allow alphanumeric characters
        return input.replaceAll("[^a-zA-Z0-9]", "");
    }
    
    /**
     * Validates that input matches expected format (numeric ID only).
     */
    public static boolean isValidId(String id) {
        if (id == null || id.isEmpty()) {
            return false;
        }
        return id.matches("^[0-9]+$");
    }
    
    /**
     * Escapes HTML to prevent XSS attacks.
     */
    public static String escapeHtml(String input) {
        if (input == null) {
            return "";
        }
        return input
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;");
    }
}

