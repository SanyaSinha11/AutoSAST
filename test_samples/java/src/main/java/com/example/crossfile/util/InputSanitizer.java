package com.example.crossfile.util;

import java.util.regex.Pattern;

public class InputSanitizer {

    private static final Pattern SAFE_STRING_PATTERN = Pattern.compile("^[a-zA-Z0-9\\s]+$");

    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
        "('|--|;|/\\*|\\*/|xp_|sp_|0x|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC|EXECUTE)",
        Pattern.CASE_INSENSITIVE
    );

    public static String sanitizeForSql(String input) {
        if (input == null) {
            return "";
        }

        String sanitized = SQL_INJECTION_PATTERN.matcher(input).replaceAll("");

        if (!SAFE_STRING_PATTERN.matcher(sanitized).matches()) {
            sanitized = sanitized.replaceAll("[^a-zA-Z0-9\\s]", "");
        }

        return sanitized.trim();
    }

    public static boolean isSafeForSql(String input) {
        if (input == null || input.isEmpty()) {
            return true;
        }
        return SAFE_STRING_PATTERN.matcher(input).matches()
            && !SQL_INJECTION_PATTERN.matcher(input).find();
    }

    public static String escapeHtml(String input) {
        if (input == null) {
            return "";
        }
        return input
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#x27;");
    }
}

