package com.acme.api;

import javax.servlet.http.*;
import java.io.*;

/**
 * Report generation endpoint.
 */
public class ReportHandler extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) 
            throws IOException {
        String format = req.getParameter("format");
        String data = req.getParameter("data");
        
        if ("pdf".equals(format)) {
            generatePdf(data, resp);
        } else {
            generateHtml(data, resp);
        }
    }

    // TP: Command injection via shell
    private void generatePdf(String data, HttpServletResponse resp) throws IOException {
        String cmd = "wkhtmltopdf - - <<< '" + data + "'";
        Process p = Runtime.getRuntime().exec(new String[]{"bash", "-c", cmd});
        
        resp.setContentType("application/pdf");
        InputStream is = p.getInputStream();
        OutputStream os = resp.getOutputStream();
        byte[] buf = new byte[4096];
        int len;
        while ((len = is.read(buf)) != -1) {
            os.write(buf, 0, len);
        }
    }

    // TP: XSS - no encoding on output
    private void generateHtml(String data, HttpServletResponse resp) throws IOException {
        resp.setContentType("text/html");
        PrintWriter out = resp.getWriter();
        out.println("<html><body>");
        out.println("<h1>Report</h1>");
        out.println("<div>" + data + "</div>");
        out.println("</body></html>");
    }
}

