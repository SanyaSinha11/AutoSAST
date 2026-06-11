package com.example.crossfile.repository;

import java.sql.*;
import java.util.*;

public class ProductRepository {

    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:mysql://localhost/shop", "user", "pass");
    }

    public List<String> findBySearchTermAndCategory(String searchTerm, String category) {
        List<String> products = new ArrayList<>();
        String sql = "SELECT name FROM products WHERE name LIKE '%" + searchTerm + "%' AND category = '" + category + "'";

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                products.add(rs.getString("name"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return products;
    }

    public String findById(Long productId) {
        String sql = "SELECT name FROM products WHERE id = ?";
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setLong(1, productId);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getString("name");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }
}

