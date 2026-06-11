package com.acme.advanced;

import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;

public class InventorySearchService {

    private Connection connection;

    public InventorySearchService(Connection conn) {
        this.connection = conn;
    }

    public String searchProducts(HttpServletRequest request) throws Exception {
        String keyword = request.getParameter("keyword");
        String sortField = request.getParameter("sort");
        
        String sanitizedKeyword = sanitizeSearchTerm(keyword);
        
        return executeSearch(sanitizedKeyword, sortField);
    }

    private String sanitizeSearchTerm(String term) {
        if (term == null) return "";
        return term.replace("'", "''").replace("--", "");
    }

    private String executeSearch(String keyword, String sortField) throws Exception {
        Statement stmt = connection.createStatement();
        String query = "SELECT * FROM inventory WHERE name LIKE '%" + keyword + "%' ORDER BY " + sortField;
        ResultSet rs = stmt.executeQuery(query);
        
        StringBuilder results = new StringBuilder();
        while (rs.next()) {
            results.append(rs.getString("name")).append("\n");
        }
        return results.toString();
    }
}
