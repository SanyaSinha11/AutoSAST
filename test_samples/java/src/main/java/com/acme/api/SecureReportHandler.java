package com.acme.api;

import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import com.acme.utils.SecurityUtils;

/**
 * Handles report generation with proper security measures.
 */
public class SecureReportHandler extends HttpServlet {

    private Connection db;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
            throws IOException {
        String reportId = req.getParameter("reportId");
        String format = req.getParameter("format");
        
        // Sanitize inputs before use
        String safeReportId = SecurityUtils.sanitizeForSql(reportId);
        
        if ("summary".equals(format)) {
            generateSummary(safeReportId, resp);
        } else if ("detailed".equals(format)) {
            generateDetailed(safeReportId, resp);
        }
    }

    // FP: Input is sanitized by SecurityUtils.sanitizeForSql before reaching here
    private void generateSummary(String reportId, HttpServletResponse resp) throws IOException {
        try {
            Statement stmt = db.createStatement();
            // This looks like SQL injection but reportId was sanitized in doGet()
            String query = "SELECT summary FROM reports WHERE id = '" + reportId + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            resp.setContentType("application/json");
            PrintWriter out = resp.getWriter();
            while (rs.next()) {
                out.println("{\"summary\":\"" + rs.getString("summary") + "\"}");
            }
        } catch (SQLException e) {
            resp.sendError(500, "Database error");
        }
    }

    // FP: Also sanitized via caller
    private void generateDetailed(String reportId, HttpServletResponse resp) throws IOException {
        try {
            Statement stmt = db.createStatement();
            String query = "SELECT * FROM reports WHERE id = '" + reportId + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            resp.setContentType("application/json");
            PrintWriter out = resp.getWriter();
            while (rs.next()) {
                out.println("{\"id\":\"" + rs.getString("id") + "\", \"data\":\"" + 
                           SecurityUtils.escapeHtml(rs.getString("data")) + "\"}");
            }
        } catch (SQLException e) {
            resp.sendError(500, "Database error");
        }
    }
}

