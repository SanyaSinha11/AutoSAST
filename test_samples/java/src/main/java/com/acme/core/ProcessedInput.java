package com.acme.core;

public class ProcessedInput {
    private final String id;
    private final String action;
    private final boolean validated;

    public ProcessedInput(String id, String action, boolean validated) {
        this.id = id;
        this.action = action;
        this.validated = validated;
    }

    public String getId() {
        return id;
    }

    public String getAction() {
        return action;
    }

    public boolean isValidated() {
        return validated;
    }
}

