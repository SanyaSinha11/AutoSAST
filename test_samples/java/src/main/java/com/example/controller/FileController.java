package com.example.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.*;

/**
 * File Controller for handling file download operations.
 */
public class FileController {

    private static final String UPLOAD_DIR = "/var/www/uploads";

    public void downloadFile(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String filename = request.getParameter("file");
        File file = new File(UPLOAD_DIR, filename);

        if (file.exists()) {
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=\"" + file.getName() + "\"");

            try (InputStream is = new FileInputStream(file);
                 OutputStream os = response.getOutputStream()) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                }
            }
        }
    }
}

