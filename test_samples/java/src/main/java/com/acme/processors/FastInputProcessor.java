package com.acme.processors;

import com.acme.core.InputProcessor;
import com.acme.core.ProcessedInput;

public class FastInputProcessor implements InputProcessor {

    @Override
    public ProcessedInput process(String id, String action) {
        return new ProcessedInput(id, action, false);
    }
}

