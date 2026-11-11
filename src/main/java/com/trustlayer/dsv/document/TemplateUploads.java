package com.trustlayer.dsv.document;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Kurumun kendi belge türünü yüklemesi: şablon JSON'u + kayıt CSV'si (+ şablonda tablo varsa tablo CSV'si).
 * Kaydetmeden önce her kayıt gerçekten basılır; eksik alan ya da sayfaya sığmayan şablon kaydedilmez.
 */
@Component
public class TemplateUploads {

    static final int MAX_FILE_BYTES = 1024 * 1024;
    static final int MAX_RECORDS = 500;

    private final PdfBoxDocumentGenerator generator;
    private final Path templateDir;
    private final Path recordDir;

    TemplateUploads(PdfBoxDocumentGenerator generator, @Value("${dsv.runtime-dir}") Path runtimeDir) {
        this.generator = generator;
        this.templateDir = PdfBoxDocumentGenerator.uploadDir(runtimeDir);
        this.recordDir = CsvRecordSource.uploadDir(runtimeDir);
    }

    /** Kaydetmeden ilk kaydın imzasız PDF'i. */
    public byte[] preview(String institutionId, String documentType, byte[] template, byte[] records, byte[] tableRows) {
        Checked c = check(institutionId, documentType, template, records, tableRows);
        Map<String, String> first = c.records.get(0);
        return generator.render(c.template, first, c.rowsOf(first), c.idOf(first)).pdf();
    }

    /** @return kaydedilen kayıt sayısı */
    public int save(String institutionId, String documentType, byte[] template, byte[] records, byte[] tableRows) {
        Checked c = check(institutionId, documentType, template, records, tableRows);
        try {
            Files.createDirectories(templateDir.resolve(institutionId));
            Files.createDirectories(recordDir.resolve(institutionId));
            Files.write(recordDir.resolve(institutionId).resolve(documentType + ".csv"), records);
            if (c.template.table() != null) {
                Files.write(recordDir.resolve(institutionId).resolve(c.template.table().source() + ".csv"), tableRows);
            }
            // Şablon en son yazılır: panel türü ancak verisi hazırken görür.
            Files.write(templateDir.resolve(institutionId).resolve(documentType + ".json"), template);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return c.records.size();
    }

    private record Checked(DocumentTemplate template, List<Map<String, String>> records,
            Map<String, List<Map<String, String>>> rowsById) {

        String idOf(Map<String, String> record) {
            return record.values().iterator().next();
        }

        List<Map<String, String>> rowsOf(Map<String, String> record) {
            return template.table() == null ? List.of() : rowsById.getOrDefault(idOf(record), List.of());
        }
    }

    private Checked check(String institutionId, String documentType, byte[] template, byte[] records, byte[] tableRows) {
        CsvRecordSource.requireId(institutionId);
        CsvRecordSource.requireId(documentType);
        DocumentTemplate t = generator.parse(limited("Şablon", template));
        List<Map<String, String>> rows = CsvRecordSource.parse("Kayıt CSV'si", lines("Kayıt CSV'si", records));
        if (rows.isEmpty()) {
            throw new IllegalArgumentException("Kayıt CSV'sinde başlık satırından sonra en az bir kayıt olmalı.");
        }
        if (rows.size() > MAX_RECORDS) {
            throw new IllegalArgumentException("En fazla " + MAX_RECORDS + " kayıt yüklenebilir.");
        }

        Map<String, List<Map<String, String>>> rowsById = Map.of();
        if (t.table() != null) {
            String source = t.table().source();
            if (source.equals(documentType) || generator.documentTypes(institutionId).stream()
                    .anyMatch(type -> type.id().equals(source))) {
                throw new IllegalArgumentException("Tablo kaynağının adı bir belge türüyle aynı olamaz: " + source);
            }
            if (tableRows == null || tableRows.length == 0) {
                throw new IllegalArgumentException("Şablonda tablo var; tablo satırları için ikinci CSV'yi (" + source
                        + ") da yükleyin.");
            }
            rowsById = CsvRecordSource.parse("Tablo CSV'si", lines("Tablo CSV'si", tableRows)).stream()
                    .collect(Collectors.groupingBy(r -> r.values().iterator().next()));
        }

        // Her kayıt basılır: eksik alan, tablo satırı olmayan kayıt, sayfaya sığmama burada yakalanır.
        Checked checked = new Checked(t, rows, rowsById);
        for (Map<String, String> record : rows) {
            String id = checked.idOf(record);
            if (t.table() != null && checked.rowsOf(record).isEmpty()) {
                throw new IllegalArgumentException("Kayıt " + id + ": tablo CSV'sinde satırı yok.");
            }
            generator.render(t, record, checked.rowsOf(record), id);
        }
        return checked;
    }

    private static byte[] limited(String name, byte[] content) {
        if (content == null || content.length == 0) {
            throw new IllegalArgumentException(name + " dosyası seçilmedi.");
        }
        if (content.length > MAX_FILE_BYTES) {
            throw new IllegalArgumentException(name + " en fazla 1 MB olabilir.");
        }
        return content;
    }

    /** UTF-8 olmayan dosya (ör. Excel'in ANSI CSV'si) Türkçe harfleri bozar; sessizce kabul etmek yerine reddedilir. */
    private static List<String> lines(String name, byte[] content) {
        try {
            return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(limited(name, content))).toString()
                    .lines().toList();
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException(name + " UTF-8 değil. Excel'de \"CSV UTF-8\" olarak kaydedin.");
        }
    }
}
