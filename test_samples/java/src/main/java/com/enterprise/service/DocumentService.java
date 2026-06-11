package com.enterprise.service;

import com.enterprise.security.PathValidator;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;

public class DocumentService {

    private final PathValidator pathValidator;

    public DocumentService(String documentsRoot) {
        this.pathValidator = new PathValidator(documentsRoot);
    }

    public byte[] getDocument(String filename) throws Exception {
        File file = pathValidator.getSecureFile(filename);
        return Files.readAllBytes(file.toPath());
    }

    public InputStream streamDocument(String filename) throws Exception {
        File file = pathValidator.getSecureFile(filename);
        return new FileInputStream(file);
    }

    public boolean documentExists(String filename) {
        try {
            pathValidator.resolveSafe(filename);
            return true;
        } catch (SecurityException e) {
            return false;
        }
    }

    public String getDocumentMetadata(String filename) throws Exception {
        File file = pathValidator.getSecureFile(filename);
        StringBuilder metadata = new StringBuilder();
        metadata.append("Name: ").append(file.getName()).append("\n");
        metadata.append("Size: ").append(file.length()).append(" bytes\n");
        metadata.append("Modified: ").append(file.lastModified());
        return metadata.toString();
    }
}

