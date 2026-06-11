package com.example.crossfile.repository;

import java.sql.*;

public class OrderRepository {

    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:mysql://localhost/shop", "user", "pass");
    }

    public String findByIdAndCustomer(String orderId, String customerName) {
        String sql = "SELECT * FROM orders WHERE order_id = '" + orderId
                   + "' AND customer_name = '" + customerName + "'";

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) {
                return "Order: " + rs.getString("order_id")
                     + " - " + rs.getString("customer_name");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return "Order not found";
    }
}

