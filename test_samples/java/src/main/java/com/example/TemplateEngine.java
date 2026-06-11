package com.example;

import java.util.HashMap;
import java.util.Map;

public class TemplateEngine {
    private static final Map<String, String> ALLOWED_TEMPLATES = new HashMap<>();
    
    static {
        ALLOWED_TEMPLATES.put("dashboard", "/templates/admin/dashboard.html");
        ALLOWED_TEMPLATES.put("users", "/templates/admin/users.html");
        ALLOWED_TEMPLATES.put("settings", "/templates/admin/settings.html");
    }

    public static String render(String templateName, String data) {
        String templatePath = ALLOWED_TEMPLATES.get(templateName);
        if (templatePath == null) {
            throw new IllegalArgumentException("Unknown template: " + templateName);
        }
        return loadAndRender(templatePath, data);
    }

    private static String loadAndRender(String path, String data) {
        return "<html><body>" + data + "</body></html>";
    }
}

