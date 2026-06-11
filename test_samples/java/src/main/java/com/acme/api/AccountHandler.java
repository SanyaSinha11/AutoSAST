package com.acme.api;

import javax.servlet.http.*;
import java.sql.*;
import java.io.*;

/**
 * Handles account-related operations.
 */
public class AccountHandler extends HttpServlet {

    private Connection db;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
            throws IOException {
        String id = req.getParameter("id");
        String action = req.getParameter("action");
        
        if ("lookup".equals(action)) {
            handleLookup(id, resp);
        } else if ("export".equals(action)) {
            handleExport(id, resp);
        }
    }

    // TP: SQL Injection - direct concatenation
    private void handleLookup(String id, HttpServletResponse resp) throws IOException {
        try {
            Statement stmt = db.createStatement();
            String query = "SELECT * FROM accounts WHERE account_id = '" + id + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            resp.setContentType("application/json");
            PrintWriter out = resp.getWriter();
            while (rs.next()) {
                out.println("{\"name\":\"" + rs.getString("name") + "\"}");
            }
        } catch (SQLException e) {
            resp.sendError(500);
        }
    }

    // FP: Uses PreparedStatement correctly
    private void handleExport(String id, HttpServletResponse resp) throws IOException {
        try {
            PreparedStatement pstmt = db.prepareStatement(
                "SELECT * FROM accounts WHERE account_id = ?"
            );
            pstmt.setString(1, id);
            ResultSet rs = pstmt.executeQuery();
            
            resp.setContentType("text/csv");
            PrintWriter out = resp.getWriter();
            while (rs.next()) {
                out.println(rs.getString("name") + "," + rs.getString("email"));
            }
        } catch (SQLException e) {
            resp.sendError(500);
        }
    }
}

