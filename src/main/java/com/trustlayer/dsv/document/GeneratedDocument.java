package com.trustlayer.dsv.document;

import java.util.UUID;

/** @param documentId QR'da da yazan belge kimliği; doğrulama sayfası bu kimlikle açılır (FR-5) */
public record GeneratedDocument(UUID documentId, byte[] pdf) {
}
