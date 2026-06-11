package com.example.crossfile.service;

import com.example.crossfile.repository.OrderRepository;

public class OrderService {

    private final OrderRepository orderRepository = new OrderRepository();

    public String findOrder(String orderId, String customerName) {
        return orderRepository.findByIdAndCustomer(orderId, customerName);
    }
}

