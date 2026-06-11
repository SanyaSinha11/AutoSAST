package com.acme.api;

import com.acme.services.AuditService;
import javax.servlet.http.*;
import java.io.*;

public class AdminController extends HttpServlet {
    
    private final AuditService auditService;
    
    public AdminController() {
        this.auditService = new AuditService();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
            throws IOException {
        String action = req.getParameter("action");
        String userId = req.getParameter("userId");
        String resource = req.getParameter("resource");
        
        if ("log".equals(action)) {
            auditService.logAccess(userId, resource);
            resp.getWriter().println("Logged");
        } else if ("logDirect".equals(action)) {
            auditService.logAccessDirect(userId, resource);
            resp.getWriter().println("Logged");
        } else if ("view".equals(action)) {
            String logs = auditService.getAuditLog(userId);
            resp.getWriter().println(logs);
        }
    }
}

