package com.acme.validation;

import java.util.regex.Pattern;

public class InputValidator {

    private static final Pattern ALPHANUMERIC = Pattern.compile("^[a-zA-Z0-9_-]+$");

    public String sanitize(String input) {
        if (input == null) {
            return "";
        }
        if (!ALPHANUMERIC.matcher(input).matches()) {
            throw new IllegalArgumentException("Invalid input format");
        }
        return input;
    }

    public boolean isValid(String input) {
        return input != null && ALPHANUMERIC.matcher(input).matches();
    }
}

