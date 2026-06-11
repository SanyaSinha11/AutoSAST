package com.acme.service;

import java.sql.*;
import com.acme.data.OrderDAO;
import com.acme.data.Order;
import com.acme.validation.InputValidator;

public class OrderProcessor {

    private OrderDAO orderDAO;
    private InputValidator validator;

    public OrderProcessor(OrderDAO orderDAO, InputValidator validator) {
        this.orderDAO = orderDAO;
        this.validator = validator;
    }

    public Order processOrder(String orderId) throws SQLException {
        String validatedId = validator.validateOrderId(orderId);
        Order order = orderDAO.findById(validatedId);
        if (order != null) {
            order.setStatus("PROCESSING");
            orderDAO.update(order);
        }
        return order;
    }

    public void cancelOrder(String orderId) throws SQLException {
        orderDAO.deleteById(orderId);
    }
}

