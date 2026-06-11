package com.example;

import java.sql.*;

public class DatabaseHelper {
    private Connection connection;

    public DatabaseHelper() {
        try {
            this.connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/app", "user", "pass");
        } catch (SQLException e) {
            throw new RuntimeException("Failed to connect to database", e);
        }
    }

    public Connection getConnection() {
        return connection;
    }

    public String executeQuery(String query) throws SQLException {
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        StringBuilder result = new StringBuilder();
        while (rs.next()) {
            result.append(rs.getString(1)).append("\n");
        }
        return result.toString();
    }

    public void executeUpdate(String query) throws SQLException {
        Statement stmt = connection.createStatement();
        stmt.executeUpdate(query);
    }

    public String getAdminData() {
        try {
            PreparedStatement stmt = connection.prepareStatement("SELECT * FROM admin_config");
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getString("config_data");
            }
        } catch (SQLException e) {
            return "{}";
        }
        return "{}";
    }

    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        } catch (SQLException ignored) {}
    }
}

