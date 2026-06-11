package com.enterprise.service;

import com.enterprise.security.QueryBuilder;
import com.enterprise.data.EmployeeRepository;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

public class EmployeeService {

    private final EmployeeRepository repository;
    private final Connection connection;

    public EmployeeService(Connection connection) {
        this.connection = connection;
        this.repository = new EmployeeRepository(connection);
    }

    public List<String> searchByDepartment(String department) {
        QueryBuilder qb = new QueryBuilder(connection);
        List<String> results = new ArrayList<>();

        try {
            PreparedStatement stmt = qb.select("employees")
                .where("department", department)
                .where("status", "active")
                .build();

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                results.add(rs.getString("name") + " - " + rs.getString("role"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return results;
    }

    public List<String> searchByName(String name) {
        QueryBuilder qb = new QueryBuilder(connection);
        List<String> results = new ArrayList<>();

        try {
            PreparedStatement stmt = qb.select("employees")
                .whereLike("name", name)
                .build();

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                results.add(rs.getString("name") + " - " + rs.getString("email"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return results;
    }

    public String getEmployeeDetails(String employeeId) {
        return repository.findById(employeeId);
    }
}

