package com.example.crossfile.service;

import com.example.crossfile.repository.ProductRepository;
import java.util.List;

public class ProductService {

    private final ProductRepository productRepository = new ProductRepository();

    public List<String> searchProducts(String searchTerm, String category) {
        return productRepository.findBySearchTermAndCategory(searchTerm, category);
    }

    public String getProductById(Long productId) {
        return productRepository.findById(productId);
    }
}

