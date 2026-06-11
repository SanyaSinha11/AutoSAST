package com.acme.api;

import javax.servlet.http.*;
import java.io.*;
import com.acme.util.TextProcessor;

/**
 * System operations endpoint.
 */
public class SystemHandler extends HttpServlet {

    private static final String[] ALLOWED = {"status", "health", "version"};

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
            throws IOException {
        String op = req.getParameter("op");
        String target = req.getParameter("target");
        
        if ("check".equals(op)) {
            runCheck(target, resp);
        } else if ("ping".equals(op)) {
            runPing(target, resp);
        }
    }

    // FP: Uses allowlist validation
    private void runCheck(String target, HttpServletResponse resp) throws IOException {
        boolean allowed = false;
        for (String a : ALLOWED) {
            if (a.equals(target)) {
                allowed = true;
                break;
            }
        }
        
        if (!allowed) {
            resp.sendError(400, "Invalid operation");
            return;
        }
        
        Process p = Runtime.getRuntime().exec(new String[]{"systemctl", target});
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        resp.setContentType("text/plain");
        PrintWriter out = resp.getWriter();
        String line;
        while ((line = reader.readLine()) != null) {
            out.println(line);
        }
    }

    // FP: Uses TextProcessor.clean and validates format
    private void runPing(String target, HttpServletResponse resp) throws IOException {
        String cleaned = TextProcessor.clean(target);
        
        if (!TextProcessor.isAlphanumeric(cleaned.replace(".", ""))) {
            resp.sendError(400, "Invalid target");
            return;
        }
        
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", cleaned);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        resp.setContentType("text/plain");
        PrintWriter out = resp.getWriter();
        String line;
        while ((line = reader.readLine()) != null) {
            out.println(line);
        }
    }
}

