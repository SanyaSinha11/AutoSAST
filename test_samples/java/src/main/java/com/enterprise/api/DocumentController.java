package com.enterprise.api;

import com.enterprise.service.DocumentService;
import javax.servlet.http.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class DocumentController extends HttpServlet {

    private DocumentService documentService;

    @Override
    public void init() {
        String docRoot = getServletContext().getInitParameter("documents.root");
        this.documentService = new DocumentService(docRoot);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String action = request.getParameter("action");
        String filename = request.getParameter("file");

        try {
            if ("download".equals(action)) {
                downloadDocument(filename, response);
            } else if ("stream".equals(action)) {
                streamDocument(filename, response);
            } else if ("info".equals(action)) {
                getDocumentInfo(filename, response);
            } else if ("exists".equals(action)) {
                checkExists(filename, response);
            } else {
                response.sendError(400, "Unknown action");
            }
        } catch (SecurityException e) {
            response.sendError(403, "Access denied");
        } catch (Exception e) {
            response.sendError(500, e.getMessage());
        }
    }

    private void downloadDocument(String filename, HttpServletResponse response) 
            throws Exception {
        byte[] content = documentService.getDocument(filename);
        response.setContentType("application/octet-stream");
        response.setContentLength(content.length);
        response.getOutputStream().write(content);
    }

    private void streamDocument(String filename, HttpServletResponse response) 
            throws Exception {
        try (InputStream is = documentService.streamDocument(filename);
             OutputStream os = response.getOutputStream()) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                os.write(buffer, 0, bytesRead);
            }
        }
    }

    private void getDocumentInfo(String filename, HttpServletResponse response) 
            throws Exception {
        String metadata = documentService.getDocumentMetadata(filename);
        response.setContentType("text/plain");
        response.getWriter().write(metadata);
    }

    private void checkExists(String filename, HttpServletResponse response) 
            throws IOException {
        boolean exists = documentService.documentExists(filename);
        response.setContentType("application/json");
        response.getWriter().write("{\"exists\": " + exists + "}");
    }
}

