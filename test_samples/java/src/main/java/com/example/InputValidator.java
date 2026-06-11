package com.example;

import java.util.regex.Pattern;

public class InputValidator {
    private static final Pattern SAFE_ID_PATTERN = Pattern.compile("^[0-9]+$");
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile("[';\"\\-\\-]|(\\/\\*)|\\b(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC)\\b", Pattern.CASE_INSENSITIVE);

    public String sanitizeInput(String input) {
        if (input == null) {
            return "";
        }
        String sanitized = input.replaceAll("[';\"\\-\\-]", "");
        sanitized = sanitized.replaceAll("(?i)(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC)", "");
        return sanitized.trim();
    }

    public boolean isValidUserId(String userId) {
        if (userId == null || userId.isEmpty()) {
            return false;
        }
        return SAFE_ID_PATTERN.matcher(userId).matches();
    }

    public int validateAndParseAccountId(String accountId) {
        if (accountId == null || accountId.isEmpty()) {
            throw new IllegalArgumentException("Account ID cannot be null or empty");
        }
        
        if (!SAFE_ID_PATTERN.matcher(accountId).matches()) {
            throw new IllegalArgumentException("Invalid account ID format");
        }
        
        int parsed = Integer.parseInt(accountId);
        if (parsed <= 0 || parsed > 999999999) {
            throw new IllegalArgumentException("Account ID out of valid range");
        }
        
        return parsed;
    }

    public boolean containsSqlInjection(String input) {
        if (input == null) {
            return false;
        }
        return SQL_INJECTION_PATTERN.matcher(input).find();
    }
}

