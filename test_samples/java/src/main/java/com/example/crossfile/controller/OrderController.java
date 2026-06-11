package com.example.crossfile.controller;

import com.example.crossfile.service.OrderService;
import com.example.crossfile.util.InputSanitizer;
import javax.servlet.http.*;
import java.io.IOException;

public class OrderController extends HttpServlet {

    private final OrderService orderService = new OrderService();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String orderId = request.getParameter("orderId");
        String customerName = request.getParameter("customerName");

        String safeOrderId = InputSanitizer.sanitizeForSql(orderId);
        String safeCustomerName = InputSanitizer.sanitizeForSql(customerName);

        String orderInfo = orderService.findOrder(safeOrderId, safeCustomerName);

        response.setContentType("text/html");
        response.getWriter().write(InputSanitizer.escapeHtml(orderInfo));
    }
}

