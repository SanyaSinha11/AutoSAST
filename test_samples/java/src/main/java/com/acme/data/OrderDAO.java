package com.acme.data;

import java.sql.*;

public class OrderDAO {

    private Connection db;

    public OrderDAO(Connection db) {
        this.db = db;
    }

    public Order findById(String orderId) throws SQLException {
        Statement stmt = db.createStatement();
        String query = "SELECT * FROM orders WHERE id = '" + orderId + "'";
        ResultSet rs = stmt.executeQuery(query);
        if (rs.next()) {
            return new Order(rs.getString("id"), rs.getString("status"));
        }
        return null;
    }

    public void deleteById(String orderId) throws SQLException {
        Statement stmt = db.createStatement();
        String query = "DELETE FROM orders WHERE id = '" + orderId + "'";
        stmt.executeUpdate(query);
    }

    public void update(Order order) throws SQLException {
        PreparedStatement pstmt = db.prepareStatement(
            "UPDATE orders SET status = ? WHERE id = ?"
        );
        pstmt.setString(1, order.getStatus());
        pstmt.setString(2, order.getId());
        pstmt.executeUpdate();
    }
}

