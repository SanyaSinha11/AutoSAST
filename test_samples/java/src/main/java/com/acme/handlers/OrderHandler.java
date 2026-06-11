package com.acme.handlers;

import com.acme.core.*;
import com.acme.processors.SecureInputProcessor;
import com.acme.data.OrderRepository;
import javax.servlet.http.*;
import java.io.*;

public class OrderHandler extends BaseRequestHandler {
    
    private final OrderRepository orderRepo;
    private final InputProcessor processor;

    public OrderHandler() {
        this.orderRepo = new OrderRepository();
        this.processor = new SecureInputProcessor();
    }

    @Override
    protected InputProcessor getInputProcessor() {
        return processor;
    }

    @Override
    protected void handleRequest(ProcessedInput input, HttpServletResponse resp) 
            throws IOException {
        String orderId = input.getId();
        String action = input.getAction();
        
        if ("details".equals(action)) {
            String result = orderRepo.findOrderById(orderId);
            resp.getWriter().println(result);
        } else if ("history".equals(action)) {
            String result = orderRepo.getOrderHistory(orderId);
            resp.getWriter().println(result);
        }
    }
}

