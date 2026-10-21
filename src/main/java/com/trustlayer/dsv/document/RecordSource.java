package com.trustlayer.dsv.document;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Şablonu dolduracak veri. İlk uygulama CSV; veritabanı gerekirse ikinci bir uygulama eklenir (FR-4). */
public interface RecordSource {

    /** Alan adı → değer. Kayıt yoksa boş. */
    Optional<Map<String, String>> find(String institutionId, String documentType, String recordId);

    /** Kayda bağlı satırlar (ör. transkriptteki dersler): {@code table} içinde ilk sütunu {@code recordId} olanlar. */
    List<Map<String, String>> findRows(String institutionId, String table, String recordId);
}
