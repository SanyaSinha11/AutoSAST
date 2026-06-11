package com.enterprise.service;

import java.util.regex.Pattern;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

public class ReportPipeline {

    private static final Pattern SAFE_IDENTIFIER = Pattern.compile("^[a-zA-Z][a-zA-Z0-9_]{0,63}$");
    private static final Pattern SQL_KEYWORDS = Pattern.compile(
        "(DROP|DELETE|INSERT|UPDATE|UNION|SELECT|;|--|'|\"|\\\\)",
        Pattern.CASE_INSENSITIVE
    );

    private final Connection connection;

    public ReportPipeline(Connection connection) {
        this.connection = connection;
    }

    public InputStage from(String tableName) {
        return new InputStage(this, tableName);
    }

    private String sanitizeIdentifier(String input) {
        if (input == null) return null;
        String cleaned = SQL_KEYWORDS.matcher(input).replaceAll("");
        if (!SAFE_IDENTIFIER.matcher(cleaned).matches()) {
            throw new IllegalArgumentException("Invalid identifier");
        }
        return cleaned;
    }

    public class InputStage {
        private final ReportPipeline pipeline;
        private final String table;
        private String column;
        private Object value;

        InputStage(ReportPipeline pipeline, String table) {
            this.pipeline = pipeline;
            this.table = sanitizeIdentifier(table);
        }

        public FilterStage where(String column, Object value) {
            this.column = sanitizeIdentifier(column);
            this.value = value;
            return new FilterStage(this);
        }
    }

    public class FilterStage {
        private final InputStage input;

        FilterStage(InputStage input) {
            this.input = input;
        }

        public List<String> execute() {
            List<String> results = new ArrayList<>();
            String sql = "SELECT * FROM " + input.table + " WHERE " + input.column + " = ?";
            
            try (PreparedStatement stmt = connection.prepareStatement(sql)) {
                stmt.setObject(1, input.value);
                ResultSet rs = stmt.executeQuery();
                while (rs.next()) {
                    results.add(rs.getString(1));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return results;
        }
    }
}

