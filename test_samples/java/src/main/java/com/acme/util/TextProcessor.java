package com.acme.util;

import java.util.regex.Pattern;

/**
 * Text processing utilities.
 */
public class TextProcessor {

    private static final Pattern DANGEROUS = Pattern.compile("[;&|`$(){}\\[\\]<>]");
    private static final Pattern PATH_CHARS = Pattern.compile("\\.\\./|\\.\\.\\\\");

    public static String clean(String input) {
        if (input == null) return "";
        return DANGEROUS.matcher(input).replaceAll("");
    }

    public static String normalizePath(String path) {
        if (path == null) return "";
        return PATH_CHARS.matcher(path).replaceAll("");
    }

    public static boolean isAlphanumeric(String s) {
        if (s == null) return false;
        return s.matches("^[a-zA-Z0-9_-]+$");
    }
}

