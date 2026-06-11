package com.acme.data;

import java.sql.*;

public class AuditRepository {
    
    private Connection connection;
    
    public AuditRepository() {
        try {
            this.connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/audit", "user", "pass");
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void recordAccess(String userId, String resource) {
        try {
            Statement stmt = connection.createStatement();
            String sql = "INSERT INTO audit_log (user_id, resource) VALUES ('" + 
                        userId + "', '" + resource + "')";
            stmt.executeUpdate(sql);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public String getLogsByUser(String userId) {
        try {
            Statement stmt = connection.createStatement();
            String sql = "SELECT * FROM audit_log WHERE user_id = '" + userId + "'";
            ResultSet rs = stmt.executeQuery(sql);
            StringBuilder sb = new StringBuilder();
            while (rs.next()) {
                sb.append(rs.getString("resource")).append("\n");
            }
            return sb.toString();
        } catch (SQLException e) {
            return "";
        }
    }
}

