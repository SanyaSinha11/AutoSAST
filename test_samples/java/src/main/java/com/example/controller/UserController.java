package com.example.controller;

import com.example.service.UserService;
import com.example.util.InputValidator;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.SQLException;

/**
 * User Controller for managing user-related operations.
 */
public class UserController {

    private final UserService userService;
    private final InputValidator validator;

    public UserController(UserService userService, InputValidator validator) {
        this.userService = userService;
        this.validator = validator;
    }

    public void searchUsers(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException {
        String searchTerm = request.getParameter("search");
        String query = "SELECT * FROM users WHERE name LIKE '%" + searchTerm + "%'";
        var results = userService.executeQuery(query);
        writeJsonResponse(response, results);
    }

    public void displayUserProfile(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String username = request.getParameter("username");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h1>Welcome, " + username + "!</h1>");
        out.println("</body></html>");
    }

    public String runSystemCommand(HttpServletRequest request) throws IOException {
        String filename = request.getParameter("filename");
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec("cat /var/log/" + filename);
        return readProcessOutput(process);
    }

    private void writeJsonResponse(HttpServletResponse response, Object data) throws IOException {
        response.setContentType("application/json");
        response.getWriter().write(data.toString());
    }

    private String readProcessOutput(Process process) throws IOException {
        StringBuilder output = new StringBuilder();
        try (var reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }
        return output.toString();
    }
}

