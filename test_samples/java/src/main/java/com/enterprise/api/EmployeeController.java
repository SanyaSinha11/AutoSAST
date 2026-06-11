package com.enterprise.api;

import com.enterprise.service.EmployeeService;
import javax.servlet.http.*;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.List;

public class EmployeeController extends HttpServlet {

    private EmployeeService employeeService;

    @Override
    public void init() {
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost/hr", "user", "pass"
            );
            this.employeeService = new EmployeeService(conn);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize", e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String action = request.getParameter("action");
        String query = request.getParameter("q");

        response.setContentType("application/json");

        try {
            String result;
            if ("search".equals(action)) {
                List<String> employees = employeeService.searchByName(query);
                result = formatAsJson(employees);
            } else if ("department".equals(action)) {
                List<String> employees = employeeService.searchByDepartment(query);
                result = formatAsJson(employees);
            } else if ("details".equals(action)) {
                result = employeeService.getEmployeeDetails(query);
            } else {
                result = "{\"error\": \"Unknown action\"}";
            }
            response.getWriter().write(result);
        } catch (Exception e) {
            response.getWriter().write("{\"error\": \"" + e.getMessage() + "\"}");
        }
    }

    private String formatAsJson(List<String> items) {
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            json.append("\"").append(escapeJson(items.get(i))).append("\"");
            if (i < items.size() - 1) json.append(",");
        }
        json.append("]");
        return json.toString();
    }

    private String escapeJson(String input) {
        return input.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n");
    }
}

