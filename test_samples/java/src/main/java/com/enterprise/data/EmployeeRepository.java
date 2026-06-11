package com.enterprise.data;

import com.enterprise.security.QueryBuilder;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class EmployeeRepository {

    private final Connection connection;

    public EmployeeRepository(Connection connection) {
        this.connection = connection;
    }

    public String findById(String employeeId) {
        QueryBuilder qb = new QueryBuilder(connection);
        
        try {
            PreparedStatement stmt = qb.select("employees")
                .where("id", employeeId)
                .build();

            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return formatEmployee(rs);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }

        return null;
    }

    public String findByEmail(String email) {
        QueryBuilder qb = new QueryBuilder(connection);
        
        try {
            PreparedStatement stmt = qb.select("employees")
                .where("email", email)
                .build();

            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return formatEmployee(rs);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }

        return null;
    }

    public String findByManager(String managerId) {
        QueryBuilder qb = new QueryBuilder(connection);
        
        try {
            PreparedStatement stmt = qb.select("employees")
                .where("manager_id", managerId)
                .where("status", "active")
                .build();

            ResultSet rs = stmt.executeQuery();
            StringBuilder result = new StringBuilder();
            while (rs.next()) {
                result.append(formatEmployee(rs)).append("\n");
            }
            return result.toString();
        } catch (SQLException e) {
            e.printStackTrace();
        }

        return null;
    }

    private String formatEmployee(ResultSet rs) throws SQLException {
        return rs.getString("name") + " (" + rs.getString("email") + ") - " 
             + rs.getString("department");
    }
}

