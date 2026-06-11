package com.acme.data;

import java.sql.*;

public class OrderRepository {
    
    private Connection connection;
    
    public OrderRepository() {
        try {
            this.connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/orders", "user", "pass");
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public String findOrderById(String orderId) {
        try {
            Statement stmt = connection.createStatement();
            String sql = "SELECT * FROM orders WHERE order_id = '" + orderId + "'";
            ResultSet rs = stmt.executeQuery(sql);
            if (rs.next()) {
                return rs.getString("order_data");
            }
        } catch (SQLException e) {
            return "{}";
        }
        return "{}";
    }

    public String getOrderHistory(String orderId) {
        try {
            PreparedStatement pstmt = connection.prepareStatement(
                "SELECT * FROM order_history WHERE order_id = ?");
            pstmt.setString(1, orderId);
            ResultSet rs = pstmt.executeQuery();
            StringBuilder sb = new StringBuilder();
            while (rs.next()) {
                sb.append(rs.getString("history_data")).append("\n");
            }
            return sb.toString();
        } catch (SQLException e) {
            return "{}";
        }
    }
}

