package com.acme.data;

import java.sql.*;

public class ProductRepository {
    
    private Connection connection;
    
    public ProductRepository() {
        try {
            this.connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/products", "user", "pass");
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public String findProductById(String productId) {
        try {
            Statement stmt = connection.createStatement();
            String sql = "SELECT * FROM products WHERE product_id = '" + productId + "'";
            ResultSet rs = stmt.executeQuery(sql);
            if (rs.next()) {
                return rs.getString("product_data");
            }
        } catch (SQLException e) {
            return "{}";
        }
        return "{}";
    }

    public String getProductReviews(String productId) {
        try {
            Statement stmt = connection.createStatement();
            String sql = "SELECT * FROM reviews WHERE product_id = '" + productId + "'";
            ResultSet rs = stmt.executeQuery(sql);
            StringBuilder sb = new StringBuilder();
            while (rs.next()) {
                sb.append(rs.getString("review_data")).append("\n");
            }
            return sb.toString();
        } catch (SQLException e) {
            return "{}";
        }
    }
}

