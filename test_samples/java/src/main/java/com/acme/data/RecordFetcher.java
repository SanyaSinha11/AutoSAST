package com.acme.data;

import java.sql.*;
import java.util.*;

/**
 * Database record operations.
 */
public class RecordFetcher {

    private Connection conn;

    public RecordFetcher(Connection conn) {
        this.conn = conn;
    }

    public List<Map<String, Object>> fetch(String table, String orderBy) throws SQLException {
        String query = "SELECT * FROM " + table + " ORDER BY " + orderBy;
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        
        List<Map<String, Object>> results = new ArrayList<>();
        ResultSetMetaData meta = rs.getMetaData();
        int cols = meta.getColumnCount();
        
        while (rs.next()) {
            Map<String, Object> row = new HashMap<>();
            for (int i = 1; i <= cols; i++) {
                row.put(meta.getColumnName(i), rs.getObject(i));
            }
            results.add(row);
        }
        return results;
    }

    public List<Map<String, Object>> fetchAllowed(String tableKey, String columnKey)
            throws SQLException {
        Map<String, String> tables = Map.of(
            "users", "app_users",
            "orders", "customer_orders",
            "items", "product_items"
        );
        Map<String, String> columns = Map.of(
            "date", "created_at",
            "name", "display_name",
            "id", "record_id"
        );
        
        String actualTable = tables.get(tableKey);
        String actualColumn = columns.get(columnKey);
        
        if (actualTable == null || actualColumn == null) {
            throw new SQLException("Invalid parameters");
        }
        
        String query = "SELECT * FROM " + actualTable + " ORDER BY " + actualColumn;
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        
        List<Map<String, Object>> results = new ArrayList<>();
        ResultSetMetaData meta = rs.getMetaData();
        int cols = meta.getColumnCount();
        
        while (rs.next()) {
            Map<String, Object> row = new HashMap<>();
            for (int i = 1; i <= cols; i++) {
                row.put(meta.getColumnName(i), rs.getObject(i));
            }
            results.add(row);
        }
        return results;
    }
}

