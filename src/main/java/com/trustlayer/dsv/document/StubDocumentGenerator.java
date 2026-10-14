package com.trustlayer.dsv.document;

import org.springframework.stereotype.Component;

/** Yer tutucu. İP-3 (Alaattin Emre) PDFBox uygulamasını yazınca bu sınıf silinir. */
@Component
class StubDocumentGenerator implements DocumentGenerator {

    @Override
    public GeneratedDocument generate(String institutionId, String documentType, String recordId) {
        throw new UnsupportedOperationException("İP-3 (Alaattin Emre): henüz yazılmadı");
    }
}
