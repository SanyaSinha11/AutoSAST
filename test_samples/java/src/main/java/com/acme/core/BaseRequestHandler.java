package com.acme.core;

import javax.servlet.http.*;
import java.io.*;

public abstract class BaseRequestHandler extends HttpServlet {
    
    protected abstract InputProcessor getInputProcessor();
    
    protected abstract void handleRequest(ProcessedInput input, HttpServletResponse resp) 
            throws IOException;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
            throws IOException {
        String rawId = req.getParameter("id");
        String rawAction = req.getParameter("action");
        
        InputProcessor processor = getInputProcessor();
        ProcessedInput input = processor.process(rawId, rawAction);
        
        handleRequest(input, resp);
    }
}

