package com.acme.processors;

import com.acme.core.InputProcessor;
import com.acme.core.ProcessedInput;
import com.acme.validation.InputValidator;

public class SecureInputProcessor implements InputProcessor {
    
    private final InputValidator validator;
    
    public SecureInputProcessor() {
        this.validator = new InputValidator();
    }

    @Override
    public ProcessedInput process(String id, String action) {
        String cleanId = validator.sanitize(id);
        String cleanAction = validator.sanitize(action);
        return new ProcessedInput(cleanId, cleanAction, true);
    }
}

