package com.enterprise.security;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class CommandExecutor {

    private static final List<String> ALLOWED_COMMANDS = Arrays.asList(
        "ping", "nslookup", "traceroute", "dig"
    );

    private static final Pattern SHELL_METACHAR = Pattern.compile(
        "[;&|`$(){}\\[\\]<>!\\\\\"']"
    );

    private static final Pattern SAFE_HOSTNAME = Pattern.compile(
        "^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$"
    );

    public boolean isAllowedCommand(String command) {
        return ALLOWED_COMMANDS.contains(command.toLowerCase().trim());
    }

    public String sanitizeArgument(String arg) {
        if (arg == null) {
            return "";
        }
        return SHELL_METACHAR.matcher(arg).replaceAll("");
    }

    public boolean isValidHostname(String hostname) {
        if (hostname == null || hostname.isEmpty()) {
            return false;
        }
        return SAFE_HOSTNAME.matcher(hostname).matches();
    }

    public String executeCommand(String command, String argument) throws Exception {
        if (!isAllowedCommand(command)) {
            throw new SecurityException("Command not allowed: " + command);
        }

        String safeArg = sanitizeArgument(argument);
        if (!isValidHostname(safeArg)) {
            throw new SecurityException("Invalid hostname format");
        }

        ProcessBuilder pb = new ProcessBuilder(command, safeArg);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("Command failed with exit code: " + exitCode);
        }

        return output.toString();
    }
}

