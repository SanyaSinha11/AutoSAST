package com.acme.advanced;

import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class CategoryBrowser {

    private static final Map<String, String> ALLOWED_CATEGORIES = new ConcurrentHashMap<>();
    private Connection connection;

    static {
        ALLOWED_CATEGORIES.put("electronics", "Electronics");
        ALLOWED_CATEGORIES.put("clothing", "Clothing");
        ALLOWED_CATEGORIES.put("books", "Books");
        ALLOWED_CATEGORIES.put("home", "Home & Garden");
    }

    public CategoryBrowser(Connection conn) {
        this.connection = conn;
    }

    public String browseByCategory(String categoryInput) throws Exception {
        String categoryKey = normalizeCategoryKey(categoryInput);
        
        if (!ALLOWED_CATEGORIES.containsKey(categoryKey)) {
            return "Invalid category";
        }
        
        String displayName = ALLOWED_CATEGORIES.get(categoryKey);
        return loadCategoryProducts(displayName);
    }

    private String normalizeCategoryKey(String input) {
        if (input == null) return "";
        return input.toLowerCase().trim();
    }

    private String loadCategoryProducts(String category) throws Exception {
        Statement stmt = connection.createStatement();
        String query = "SELECT name, price FROM products WHERE category = '" + category + "'";
        ResultSet rs = stmt.executeQuery(query);
        
        StringBuilder result = new StringBuilder();
        while (rs.next()) {
            result.append(rs.getString("name")).append(": $").append(rs.getDouble("price")).append("\n");
        }
        return result.toString();
    }
}
