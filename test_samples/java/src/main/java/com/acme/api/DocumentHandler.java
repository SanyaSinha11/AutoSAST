package com.acme.api;

import javax.servlet.http.*;
import java.io.*;
import java.nio.file.*;

/**
 * Document management endpoint.
 */
public class DocumentHandler extends HttpServlet {
    
    private static final String BASE = "/data/documents";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
            throws IOException {
        String name = req.getParameter("name");
        String mode = req.getParameter("mode");
        
        if ("preview".equals(mode)) {
            servePreview(name, resp);
        } else {
            serveDocument(name, resp);
        }
    }

    // TP: Path traversal - no validation
    private void serveDocument(String name, HttpServletResponse resp) throws IOException {
        File f = new File(BASE, name);
        if (f.exists()) {
            resp.setContentType("application/octet-stream");
            Files.copy(f.toPath(), resp.getOutputStream());
        } else {
            resp.sendError(404);
        }
    }

    // FP: Validates canonical path is within base directory
    private void servePreview(String name, HttpServletResponse resp) throws IOException {
        File base = new File(BASE);
        File target = new File(base, name);
        
        String canonicalBase = base.getCanonicalPath();
        String canonicalTarget = target.getCanonicalPath();
        
        if (!canonicalTarget.startsWith(canonicalBase)) {
            resp.sendError(403, "Access denied");
            return;
        }
        
        if (target.exists()) {
            resp.setContentType("text/plain");
            BufferedReader reader = new BufferedReader(new FileReader(target));
            String line;
            PrintWriter out = resp.getWriter();
            int count = 0;
            while ((line = reader.readLine()) != null && count < 10) {
                out.println(line);
                count++;
            }
            reader.close();
        }
    }
}

