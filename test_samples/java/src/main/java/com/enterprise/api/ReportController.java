package com.enterprise.api;

import com.enterprise.service.ReportPipeline;
import javax.servlet.http.*;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.List;

public class ReportController extends HttpServlet {

    private ReportPipeline pipeline;

    @Override
    public void init() {
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost/reports", "user", "pass"
            );
            this.pipeline = new ReportPipeline(conn);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize", e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String table = request.getParameter("table");
        String column = request.getParameter("column");
        String value = request.getParameter("value");

        response.setContentType("application/json");

        try {
            List<String> results = pipeline.from(table)
                                           .where(column, value)
                                           .execute();
            
            StringBuilder json = new StringBuilder("[");
            for (int i = 0; i < results.size(); i++) {
                json.append("\"").append(escapeJson(results.get(i))).append("\"");
                if (i < results.size() - 1) json.append(",");
            }
            json.append("]");
            
            response.getWriter().write(json.toString());
        } catch (IllegalArgumentException e) {
            response.setStatus(400);
            response.getWriter().write("{\"error\": \"Invalid input\"}");
        } catch (Exception e) {
            response.setStatus(500);
            response.getWriter().write("{\"error\": \"" + escapeJson(e.getMessage()) + "\"}");
        }
    }

    private String escapeJson(String input) {
        if (input == null) return "";
        return input.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n");
    }
}

