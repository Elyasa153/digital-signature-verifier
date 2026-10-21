package com.trustlayer.dsv.document;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * {@code <records-dir>/<kurum>/<tür>.csv} dosyalarını okur. Ayraç noktalı virgül, ilk satır başlık,
 * ilk sütun kayıt numarası (K9).
 */
@Component
class CsvRecordSource implements RecordSource {

    /** Kurum ve tür adları dosya yoluna girer; {@code ../} gibi değerler buradan geçemez. */
    private static final Pattern ID = Pattern.compile("[a-z0-9-]+");

    private final Path dir;

    CsvRecordSource(@Value("${dsv.records-dir}") Path dir) {
        this.dir = dir;
    }

    static String requireId(String id) {
        if (id == null || !ID.matcher(id).matches()) {
            throw new IllegalArgumentException("Geçersiz kimlik: " + id);
        }
        return id;
    }

    @Override
    public Optional<Map<String, String>> find(String institutionId, String documentType, String recordId) {
        return rows(institutionId, documentType, recordId).stream().findFirst();
    }

    @Override
    public List<Map<String, String>> findRows(String institutionId, String table, String recordId) {
        return rows(institutionId, table, recordId);
    }

    // Sınır: değer içinde ';' ve tırnaklı alan desteklenmez; sentetik veride yok, gerekirse CSV kütüphanesi.
    private List<Map<String, String>> rows(String institutionId, String file, String recordId) {
        Path csv = dir.resolve(requireId(institutionId)).resolve(requireId(file) + ".csv");
        if (!Files.exists(csv)) {
            return List.of();
        }
        List<String> lines;
        try {
            lines = Files.readAllLines(csv, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        if (lines.isEmpty()) {
            return List.of();
        }
        String[] header = lines.get(0).replace("﻿", "").split(";", -1);
        List<Map<String, String>> result = new ArrayList<>();
        for (int i = 1; i < lines.size(); i++) {
            if (lines.get(i).isBlank()) {
                continue;
            }
            String[] cells = lines.get(i).split(";", -1);
            if (cells.length != header.length) {
                throw new IllegalArgumentException(csv.getFileName() + " satır " + (i + 1) + ": "
                        + header.length + " sütun bekleniyordu, " + cells.length + " var");
            }
            if (!cells[0].trim().equals(recordId)) {
                continue;
            }
            Map<String, String> row = new LinkedHashMap<>();
            for (int c = 0; c < header.length; c++) {
                row.put(header[c].trim(), cells[c].trim());
            }
            result.add(row);
        }
        return result;
    }
}
