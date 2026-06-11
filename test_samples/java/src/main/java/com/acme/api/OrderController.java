package com.acme.api;

import javax.servlet.http.*;
import java.io.*;
import com.acme.service.OrderProcessor;
import com.acme.validation.InputValidator;
import com.acme.data.Order;

public class OrderController extends HttpServlet {

    private OrderProcessor orderProcessor;
    private InputValidator validator;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        String orderId = req.getParameter("orderId");
        String action = req.getParameter("action");

        try {
            if ("process".equals(action)) {
                String safeOrderId = validator.validateOrderId(orderId);
                Order order = orderProcessor.processOrder(safeOrderId);
                writeJsonResponse(resp, order);
            } else if ("cancel".equals(action)) {
                orderProcessor.cancelOrder(orderId);
                resp.setStatus(200);
            }
        } catch (Exception e) {
            resp.sendError(500, e.getMessage());
        }
    }

    private void writeJsonResponse(HttpServletResponse resp, Order order) throws IOException {
        resp.setContentType("application/json");
        PrintWriter out = resp.getWriter();
        if (order != null) {
            out.println("{\"id\":\"" + order.getId() + "\", \"status\":\"" + order.getStatus() + "\"}");
        } else {
            out.println("{\"error\":\"Order not found\"}");
        }
    }
}

