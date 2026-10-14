package com.trustlayer.dsv.document;

import java.util.Map;
import java.util.Optional;

/** Şablonu dolduracak veri. İlk uygulama CSV; veritabanı gerekirse ikinci bir uygulama eklenir (FR-4). */
public interface RecordSource {

    /** Alan adı → değer. Kayıt yoksa boş. */
    Optional<Map<String, String>> find(String institutionId, String documentType, String recordId);
}
