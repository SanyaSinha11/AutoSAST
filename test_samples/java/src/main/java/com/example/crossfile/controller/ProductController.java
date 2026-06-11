package com.example.crossfile.controller;

import com.example.crossfile.service.ProductService;
import javax.servlet.http.*;
import java.io.IOException;
import java.util.List;

public class ProductController extends HttpServlet {

    private final ProductService productService = new ProductService();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String searchTerm = request.getParameter("search");
        String category = request.getParameter("category");

        List<String> products = productService.searchProducts(searchTerm, category);

        response.setContentType("application/json");
        response.getWriter().write(products.toString());
    }
}

