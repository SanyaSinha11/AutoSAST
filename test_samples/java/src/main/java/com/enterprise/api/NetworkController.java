package com.enterprise.api;

import com.enterprise.service.NetworkService;
import javax.servlet.http.*;
import java.io.IOException;

public class NetworkController extends HttpServlet {

    private final NetworkService networkService = new NetworkService();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String action = request.getParameter("action");
        String target = request.getParameter("target");

        response.setContentType("application/json");

        try {
            String result;
            if ("ping".equals(action)) {
                result = networkService.pingHost(target);
            } else if ("dns".equals(action)) {
                result = networkService.lookupDns(target);
            } else if ("fetch".equals(action)) {
                result = networkService.fetchFromCdn(target);
            } else if ("check".equals(action)) {
                boolean reachable = networkService.isHostReachable(target);
                result = "{\"reachable\": " + reachable + "}";
            } else {
                result = "{\"error\": \"Unknown action\"}";
            }
            response.getWriter().write(formatResult(result));
        } catch (SecurityException e) {
            response.setStatus(403);
            response.getWriter().write("{\"error\": \"" + escapeJson(e.getMessage()) + "\"}");
        } catch (Exception e) {
            response.setStatus(500);
            response.getWriter().write("{\"error\": \"" + escapeJson(e.getMessage()) + "\"}");
        }
    }

    private String formatResult(String result) {
        if (result.startsWith("{")) {
            return result;
        }
        return "{\"output\": \"" + escapeJson(result) + "\"}";
    }

    private String escapeJson(String input) {
        if (input == null) return "";
        return input.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r");
    }
}

