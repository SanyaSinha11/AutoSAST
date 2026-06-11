package com.enterprise.security;

import java.sql.PreparedStatement;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Map;
import java.util.HashMap;

public class QueryBuilder {

    private final Connection connection;
    private final Map<String, Object> parameters = new HashMap<>();
    private String baseQuery;
    private int paramIndex = 1;

    public QueryBuilder(Connection connection) {
        this.connection = connection;
    }

    public QueryBuilder select(String table) {
        this.baseQuery = "SELECT * FROM " + table;
        return this;
    }

    public QueryBuilder where(String column, Object value) {
        if (baseQuery.contains("WHERE")) {
            baseQuery += " AND " + column + " = ?";
        } else {
            baseQuery += " WHERE " + column + " = ?";
        }
        parameters.put(String.valueOf(paramIndex++), value);
        return this;
    }

    public QueryBuilder whereLike(String column, Object value) {
        if (baseQuery.contains("WHERE")) {
            baseQuery += " AND " + column + " LIKE ?";
        } else {
            baseQuery += " WHERE " + column + " LIKE ?";
        }
        parameters.put(String.valueOf(paramIndex++), "%" + value + "%");
        return this;
    }

    public PreparedStatement build() throws SQLException {
        PreparedStatement stmt = connection.prepareStatement(baseQuery);
        for (Map.Entry<String, Object> entry : parameters.entrySet()) {
            int idx = Integer.parseInt(entry.getKey());
            stmt.setObject(idx, entry.getValue());
        }
        return stmt;
    }

    public String getQuery() {
        return baseQuery;
    }
}

