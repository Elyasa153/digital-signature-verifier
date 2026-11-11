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
 * {@code <kurum>/<tür>.csv} dosyalarını okur: önce kurumların yüklediği {@code <runtime>/kayitlar}, sonra örnek veri
 * {@code <records-dir>}. Ayraç noktalı virgül, ilk satır başlık, ilk sütun kayıt numarası (K9).
 */
@Component
class CsvRecordSource implements RecordSource {

    /** Kurum ve tür adları dosya yoluna girer; {@code ../} gibi değerler buradan geçemez. */
    private static final Pattern ID = Pattern.compile("[a-z0-9-]+");

    private final List<Path> dirs;

    CsvRecordSource(@Value("${dsv.runtime-dir}") Path runtimeDir, @Value("${dsv.records-dir}") Path dir) {
        this.dirs = List.of(uploadDir(runtimeDir), dir);
    }

    /** Kurumların yüklediği CSV'ler. */
    static Path uploadDir(Path runtimeDir) {
        return runtimeDir.resolve("kayitlar");
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

    @Override
    public Optional<String> firstRecordId(String institutionId, String documentType) {
        Path csv = locate(institutionId, documentType);
        try {
            return csv == null ? Optional.empty()
                    : parse(csv.getFileName().toString(), Files.readAllLines(csv, StandardCharsets.UTF_8)).stream()
                            .findFirst().map(row -> row.values().iterator().next());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private Path locate(String institutionId, String file) {
        for (Path dir : dirs) {
            Path candidate = dir.resolve(requireId(institutionId)).resolve(requireId(file) + ".csv");
            if (Files.exists(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private List<Map<String, String>> rows(String institutionId, String file, String recordId) {
        Path csv = locate(institutionId, file);
        if (csv == null) {
            return List.of();
        }
        try {
            return parse(csv.getFileName().toString(), Files.readAllLines(csv, StandardCharsets.UTF_8)).stream()
                    .filter(row -> row.values().iterator().next().equals(recordId)).toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Bütün satırlar; her satır başlık → değer, sırası korunur. */
    // Sınır: değer içinde ';' ve tırnaklı alan desteklenmez; sentetik veride yok, gerekirse CSV kütüphanesi.
    static List<Map<String, String>> parse(String name, List<String> lines) {
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
                throw new IllegalArgumentException(name + " satır " + (i + 1) + ": "
                        + header.length + " sütun bekleniyordu, " + cells.length + " var");
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
