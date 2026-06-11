package com.enterprise.service;

import com.enterprise.security.CommandExecutor;
import com.enterprise.security.UrlValidator;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class NetworkService {

    private final CommandExecutor commandExecutor;
    private final UrlValidator urlValidator;

    public NetworkService() {
        this.commandExecutor = new CommandExecutor();
        this.urlValidator = new UrlValidator();
    }

    public String pingHost(String hostname) throws Exception {
        return commandExecutor.executeCommand("ping", hostname);
    }

    public String lookupDns(String hostname) throws Exception {
        return commandExecutor.executeCommand("nslookup", hostname);
    }

    public String fetchFromCdn(String urlString) throws Exception {
        String validatedUrl = urlValidator.validateAndNormalize(urlString);
        
        URL url = new URL(validatedUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);

        StringBuilder response = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
        }

        return response.toString();
    }

    public boolean isHostReachable(String hostname) {
        try {
            commandExecutor.executeCommand("ping", hostname);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}

