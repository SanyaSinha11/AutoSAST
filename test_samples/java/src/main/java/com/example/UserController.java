package com.example;

import java.sql.*;
import javax.servlet.http.*;

public class UserController {
    private DatabaseHelper dbHelper;
    private InputValidator validator;
    private HtmlEncoder encoder;

    public UserController() {
        this.dbHelper = new DatabaseHelper();
        this.validator = new InputValidator();
        this.encoder = new HtmlEncoder();
    }

    public String getUserProfile(HttpServletRequest request) throws SQLException {
        String userId = request.getParameter("id");
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        return dbHelper.executeQuery(query);
    }

    public String searchUsers(HttpServletRequest request) throws SQLException {
        String searchTerm = request.getParameter("q");
        String sanitized = validator.sanitizeInput(searchTerm);
        String query = "SELECT * FROM users WHERE name LIKE '%" + sanitized + "%'";
        return dbHelper.executeQuery(query);
    }

    public void updateUserEmail(HttpServletRequest request) throws SQLException {
        String userId = request.getParameter("userId");
        String email = request.getParameter("email");
        
        if (!validator.isValidUserId(userId)) {
            throw new IllegalArgumentException("Invalid user ID");
        }
        
        String query = "UPDATE users SET email = '" + email + "' WHERE id = " + userId;
        dbHelper.executeUpdate(query);
    }

    public String displayComment(HttpServletRequest request) {
        String comment = request.getParameter("comment");
        return "<div class='comment'>" + comment + "</div>";
    }

    public String displayUserName(HttpServletRequest request) {
        String name = request.getParameter("name");
        String safeName = encoder.encode(name);
        return "<span class='username'>" + safeName + "</span>";
    }

    public void processPayment(HttpServletRequest request) throws SQLException {
        String amount = request.getParameter("amount");
        String accountId = request.getParameter("accountId");
        
        double parsedAmount = Double.parseDouble(amount);
        int validatedAccountId = validator.validateAndParseAccountId(accountId);
        
        String query = "INSERT INTO payments (account_id, amount) VALUES (" + validatedAccountId + ", " + parsedAmount + ")";
        dbHelper.executeUpdate(query);
    }

    public String renderAdminPanel(HttpServletRequest request) {
        String template = request.getParameter("template");
        String data = dbHelper.getAdminData();
        return TemplateEngine.render(template, data);
    }

    public void deleteUser(HttpServletRequest request) throws SQLException {
        String userId = request.getParameter("id");
        PreparedStatement stmt = dbHelper.getConnection().prepareStatement("DELETE FROM users WHERE id = ?");
        stmt.setString(1, userId);
        stmt.executeUpdate();
    }
}

