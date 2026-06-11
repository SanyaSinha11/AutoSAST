package com.acme.advanced;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;
import java.util.regex.Pattern;

public class OrderLookupController {

    private static final Pattern ORDER_ID_PATTERN = Pattern.compile("^ORD-[0-9]{6}$");
    private Connection dbConnection;

    public OrderLookupController(Connection conn) {
        this.dbConnection = conn;
    }

    public String lookupOrder(HttpServletRequest request) throws Exception {
        String orderId = request.getParameter("orderId");
        
        if (!isValidOrderId(orderId)) {
            throw new IllegalArgumentException("Invalid order ID format");
        }
        
        return retrieveOrderDetails(orderId);
    }

    private boolean isValidOrderId(String id) {
        return id != null && ORDER_ID_PATTERN.matcher(id).matches();
    }

    private String retrieveOrderDetails(String orderId) throws Exception {
        String sql = "SELECT order_date, total FROM orders WHERE order_id = '" + orderId + "'";
        PreparedStatement stmt = dbConnection.prepareStatement(sql);
        ResultSet rs = stmt.executeQuery();
        
        if (rs.next()) {
            return rs.getString("order_date") + ": $" + rs.getDouble("total");
        }
        return "Order not found";
    }
}
