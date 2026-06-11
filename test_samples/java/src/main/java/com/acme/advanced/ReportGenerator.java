package com.acme.advanced;

import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;

public class ReportGenerator {

    private Connection connection;

    public ReportGenerator(Connection conn) {
        this.connection = conn;
    }

    public String generateReport(HttpServletRequest request) throws Exception {
        String reportType = request.getParameter("type");
        String dateRange = request.getParameter("range");
        String filterValue = request.getParameter("filter");

        String tableName = getTableForType(reportType);
        String dateColumn = getDateColumn(reportType);
        String filterClause = buildFilterClause(filterValue);

        return fetchReportData(tableName, dateColumn, dateRange, filterClause);
    }

    private String getTableForType(String type) {
        switch (type != null ? type : "default") {
            case "sales": return "sales_data";
            case "inventory": return "inventory_log";
            default: return "general_reports";
        }
    }

    private String getDateColumn(String type) {
        switch (type != null ? type : "default") {
            case "sales": return "sale_date";
            case "inventory": return "log_date";
            default: return "created_at";
        }
    }

    private String buildFilterClause(String filter) {
        if (filter != null && !filter.isEmpty()) {
            return " AND category = '" + filter + "'";
        }
        return "";
    }

    private String fetchReportData(String table, String dateCol, String range, String filter) throws Exception {
        Statement stmt = connection.createStatement();
        String sql = "SELECT * FROM " + table + " WHERE " + dateCol + " > '2024-01-01'" + filter;
        ResultSet rs = stmt.executeQuery(sql);
        
        StringBuilder sb = new StringBuilder();
        while (rs.next()) {
            sb.append(rs.getString(1)).append(",");
        }
        return sb.toString();
    }
}
