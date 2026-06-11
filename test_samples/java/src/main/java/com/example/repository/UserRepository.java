package com.example.repository;

import java.sql.*;
import javax.sql.DataSource;

/**
 * User Repository - Data access layer for user operations.
 */
public class UserRepository {

    private final DataSource dataSource;

    public UserRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public String getUserBio(int userId) throws SQLException {
        String query = "SELECT bio FROM user_profiles WHERE user_id = ?";
        
        try (Connection conn = dataSource.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setInt(1, userId);
            
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("bio");
                }
                return null;
            }
        }
    }
}

