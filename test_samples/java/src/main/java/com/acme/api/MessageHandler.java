package com.acme.api;

import javax.servlet.http.*;
import java.io.*;
import org.apache.commons.text.StringEscapeUtils;

/**
 * Message display endpoint.
 */
public class MessageHandler extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
            throws IOException {
        String content = req.getParameter("content");
        String template = req.getParameter("template");
        
        if ("rich".equals(template)) {
            renderRich(content, resp);
        } else {
            renderPlain(content, resp);
        }
    }

    // FP: Uses StringEscapeUtils.escapeHtml4 for encoding
    private void renderRich(String content, HttpServletResponse resp) throws IOException {
        resp.setContentType("text/html");
        PrintWriter out = resp.getWriter();
        out.println("<html><body>");
        out.println("<div class='message'>");
        out.println(StringEscapeUtils.escapeHtml4(content));
        out.println("</div>");
        out.println("</body></html>");
    }

    // FP: Content-Type is text/plain, browser won't execute scripts
    private void renderPlain(String content, HttpServletResponse resp) throws IOException {
        resp.setContentType("text/plain; charset=utf-8");
        resp.setHeader("X-Content-Type-Options", "nosniff");
        PrintWriter out = resp.getWriter();
        out.println("Message: " + content);
    }
}

