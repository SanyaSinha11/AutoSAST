package com.enterprise.security;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

public class PathValidator {

    private static final List<String> BLOCKED_PATTERNS = Arrays.asList(
        "..", "~", "$", "%", "|", ";", "&", "`"
    );

    private final Path baseDirectory;

    public PathValidator(String baseDir) {
        this.baseDirectory = Paths.get(baseDir).toAbsolutePath().normalize();
    }

    public boolean isWithinBase(String requestedPath) {
        try {
            Path resolved = baseDirectory.resolve(requestedPath).normalize();
            return resolved.startsWith(baseDirectory);
        } catch (Exception e) {
            return false;
        }
    }

    public String sanitizePath(String input) {
        if (input == null) {
            return "";
        }
        String result = input;
        for (String pattern : BLOCKED_PATTERNS) {
            result = result.replace(pattern, "");
        }
        return result;
    }

    public Path resolveSafe(String requestedPath) throws SecurityException {
        String sanitized = sanitizePath(requestedPath);
        Path resolved = baseDirectory.resolve(sanitized).normalize();
        
        if (!resolved.startsWith(baseDirectory)) {
            throw new SecurityException("Path traversal attempt detected");
        }
        return resolved;
    }

    public File getSecureFile(String filename) throws SecurityException, IOException {
        Path safePath = resolveSafe(filename);
        File file = safePath.toFile();
        
        if (!file.exists()) {
            throw new IOException("File not found");
        }
        if (!file.canRead()) {
            throw new SecurityException("Access denied");
        }
        return file;
    }
}

