package com.acme.handlers;

import com.acme.core.*;
import com.acme.processors.FastInputProcessor;
import com.acme.data.ProductRepository;
import javax.servlet.http.*;
import java.io.*;

public class ProductHandler extends BaseRequestHandler {
    
    private final ProductRepository productRepo;
    private final InputProcessor processor;

    public ProductHandler() {
        this.productRepo = new ProductRepository();
        this.processor = new FastInputProcessor();
    }

    @Override
    protected InputProcessor getInputProcessor() {
        return processor;
    }

    @Override
    protected void handleRequest(ProcessedInput input, HttpServletResponse resp) 
            throws IOException {
        String productId = input.getId();
        String action = input.getAction();
        
        if ("info".equals(action)) {
            String result = productRepo.findProductById(productId);
            resp.getWriter().println(result);
        } else if ("reviews".equals(action)) {
            String result = productRepo.getProductReviews(productId);
            resp.getWriter().println(result);
        }
    }
}

