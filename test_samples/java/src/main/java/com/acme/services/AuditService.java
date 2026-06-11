package com.acme.services;

import com.acme.data.AuditRepository;
import com.acme.validation.InputValidator;

public class AuditService {
    
    private final AuditRepository auditRepo;
    private final InputValidator validator;
    
    public AuditService() {
        this.auditRepo = new AuditRepository();
        this.validator = new InputValidator();
    }

    public void logAccess(String userId, String resource) {
        String cleanUserId = validator.sanitize(userId);
        auditRepo.recordAccess(cleanUserId, resource);
    }

    public void logAccessDirect(String userId, String resource) {
        auditRepo.recordAccess(userId, resource);
    }

    public String getAuditLog(String userId) {
        return auditRepo.getLogsByUser(userId);
    }
}

