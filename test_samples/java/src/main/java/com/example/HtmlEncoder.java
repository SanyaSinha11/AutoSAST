package com.example;

public class HtmlEncoder {
    
    public String encode(String input) {
        if (input == null) {
            return "";
        }
        
        StringBuilder encoded = new StringBuilder();
        for (char c : input.toCharArray()) {
            switch (c) {
                case '<':
                    encoded.append("&lt;");
                    break;
                case '>':
                    encoded.append("&gt;");
                    break;
                case '&':
                    encoded.append("&amp;");
                    break;
                case '"':
                    encoded.append("&quot;");
                    break;
                case '\'':
                    encoded.append("&#x27;");
                    break;
                default:
                    encoded.append(c);
            }
        }
        return encoded.toString();
    }

    public String encodeForAttribute(String input) {
        return encode(input);
    }

    public String encodeForJavaScript(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("\\", "\\\\")
                   .replace("'", "\\'")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r");
    }
}

