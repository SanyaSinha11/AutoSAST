package com.acme.advanced;

import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UserProfileService {

    private Connection connection;
    private InputValidator validator;

    public UserProfileService(Connection conn, InputValidator validator) {
        this.connection = conn;
        this.validator = validator;
    }

    public String getUserProfile(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        String sanitizedId = validator.sanitizeNumericInput(userId);
        return fetchProfile(sanitizedId);
    }

    private String fetchProfile(String id) throws Exception {
        Statement stmt = connection.createStatement();
        String query = "SELECT * FROM users WHERE id = '" + id + "'";
        ResultSet rs = stmt.executeQuery(query);
        if (rs.next()) {
            return rs.getString("name");
        }
        return null;
    }
}

class InputValidator {
    public String sanitizeNumericInput(String input) {
        if (input == null) return "0";
        return input.replaceAll("[^0-9]", "");
    }
}
