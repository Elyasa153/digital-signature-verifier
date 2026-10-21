package com.trustlayer.dsv.document;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import tools.jackson.databind.json.JsonMapper;

/** Şablon + CSV kaydı → tek sayfalık A4 PDF, sağ altta doğrulama QR'ı (FR-3..FR-5). */
@Component
class PdfBoxDocumentGenerator implements DocumentGenerator {

    static final String QR_WARNING = "Bu QR kod belgeyi doğrulamaz, yalnızca doğrulama sayfasına yönlendirir. "
            + "Belgenin geçerliliği, PDF dosyasındaki elektronik imzanın bu sayfada kontrol edilmesiyle anlaşılır.";

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{(\\w+)}");
    private static final PDRectangle PAGE = PDRectangle.A4;
    private static final float MARGIN = 56;
    private static final float QR_SIZE = 96;
    private static final float CONTENT_WIDTH = PAGE.getWidth() - 2 * MARGIN;
    private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("dd.MM.yyyy");
    private static final ZoneId ZONE = ZoneId.of("Europe/Istanbul");

    private final RecordSource records;
    private final String verifyBaseUrl;
    private final JsonMapper json = JsonMapper.builder().build();

    PdfBoxDocumentGenerator(RecordSource records, @Value("${dsv.verify-base-url}") String verifyBaseUrl) {
        this.records = records;
        this.verifyBaseUrl = verifyBaseUrl;
    }

    @Override
    public GeneratedDocument generate(String institutionId, String documentType, String recordId) {
        DocumentTemplate template = loadTemplate(institutionId, documentType);
        Map<String, String> record = records.find(institutionId, documentType, recordId)
                .orElseThrow(() -> new IllegalArgumentException("Kayıt bulunamadı: " + recordId));
        List<Map<String, String>> rows = List.of();
        if (template.table() != null) {
            rows = records.findRows(institutionId, template.table().source(), recordId);
            if (rows.isEmpty()) {
                throw new IllegalArgumentException("Kayıt " + recordId + ": " + template.table().source() + " satırı yok");
            }
        }
        UUID documentId = UUID.randomUUID();
        try {
            return new GeneratedDocument(documentId, render(template, record, rows, recordId, documentId));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private DocumentTemplate loadTemplate(String institutionId, String documentType) {
        String path = "document-templates/" + CsvRecordSource.requireId(institutionId) + "/"
                + CsvRecordSource.requireId(documentType) + ".json";
        try (InputStream in = getClass().getClassLoader().getResourceAsStream(path)) {
            if (in == null) {
                throw new IllegalArgumentException("Şablon yok: " + institutionId + "/" + documentType);
            }
            return json.readValue(in, DocumentTemplate.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private byte[] render(DocumentTemplate t, Map<String, String> record, List<Map<String, String>> rows,
            String recordId, UUID documentId) throws IOException {
        try (PDDocument doc = new PDDocument()) {
            PDPage page = new PDPage(PAGE);
            doc.addPage(page);
            PDFont regular = font(doc, "NotoSans-Regular.ttf");
            PDFont bold = font(doc, "NotoSans-Bold.ttf");

            try (PDPageContentStream cs = new PDPageContentStream(doc, page)) {
                // İçerik QR bloğunun üstünde bitmeli.
                Pen pen = new Pen(cs, PAGE.getHeight() - MARGIN, MARGIN + QR_SIZE + 24);

                pen.write(bold, 11, MARGIN, t.issuer());
                pen.down(40);
                pen.write(bold, 18, MARGIN + (CONTENT_WIDTH - width(bold, 18, t.title())) / 2, t.title());
                pen.down(36);

                if (t.intro() != null) {
                    pen.paragraph(regular, 11, MARGIN, CONTENT_WIDTH, fill(t.intro(), record, recordId));
                    pen.down(12);
                }
                for (DocumentTemplate.Field f : t.fields()) {
                    pen.write(bold, 11, MARGIN, f.label() + ":");
                    pen.paragraph(regular, 11, MARGIN + 150, CONTENT_WIDTH - 150, value(record, f.key(), recordId));
                }
                if (t.table() != null) {
                    pen.down(12);
                    table(pen, regular, bold, t.table().columns(), rows, recordId);
                }
                if (t.closing() != null) {
                    pen.down(12);
                    pen.paragraph(bold, 11, MARGIN, CONTENT_WIDTH, fill(t.closing(), record, recordId));
                }

                footer(cs, regular, documentId);
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            return out.toByteArray();
        }
    }

    private static void table(Pen pen, PDFont regular, PDFont bold, List<DocumentTemplate.Field> columns,
            List<Map<String, String>> rows, String recordId) throws IOException {
        float fixed = 0;
        int flexible = 0;
        for (DocumentTemplate.Field c : columns) {
            if (c.width() == null) {
                flexible++;
            } else {
                fixed += c.width();
            }
        }
        float flexWidth = flexible == 0 ? 0 : (CONTENT_WIDTH - fixed) / flexible;

        float x = MARGIN;
        for (DocumentTemplate.Field c : columns) {
            pen.write(bold, 10, x, c.label());
            x += c.width() == null ? flexWidth : c.width();
        }
        pen.down(4);
        pen.rule(MARGIN, CONTENT_WIDTH);
        pen.down(12);
        for (Map<String, String> row : rows) {
            x = MARGIN;
            for (DocumentTemplate.Field c : columns) {
                pen.write(regular, 10, x, value(row, c.key(), recordId));
                x += c.width() == null ? flexWidth : c.width();
            }
            pen.down(15);
        }
    }

    private void footer(PDPageContentStream cs, PDFont regular, UUID documentId) throws IOException {
        float qrX = PAGE.getWidth() - MARGIN - QR_SIZE;
        qr(cs, verifyBaseUrl + "?belge=" + documentId, qrX, MARGIN);

        Pen pen = new Pen(cs, MARGIN + QR_SIZE - 8, 0);
        float textWidth = qrX - MARGIN - 16;
        pen.write(regular, 9, MARGIN, "Düzenlenme tarihi: " + LocalDate.now(ZONE).format(DATE));
        pen.down(13);
        pen.write(regular, 9, MARGIN, "Belge no: " + documentId);
        pen.down(17);
        pen.paragraph(regular, 8, MARGIN, textWidth, QR_WARNING);
    }

    /** QR vektör olarak çizilir: her modül bir kare, resim gömülmez. */
    private static void qr(PDPageContentStream cs, String url, float x, float y) throws IOException {
        BitMatrix m;
        try {
            m = new QRCodeWriter().encode(url, BarcodeFormat.QR_CODE, 0, 0, Map.of(
                    EncodeHintType.MARGIN, 0,
                    EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M,
                    EncodeHintType.CHARACTER_SET, "UTF-8"));
        } catch (WriterException e) {
            throw new IllegalStateException("QR üretilemedi", e);
        }
        float cell = QR_SIZE / m.getWidth();
        for (int row = 0; row < m.getHeight(); row++) {
            for (int col = 0; col < m.getWidth(); col++) {
                if (m.get(col, row)) {
                    cs.addRect(x + col * cell, y + QR_SIZE - (row + 1) * cell, cell, cell);
                }
            }
        }
        cs.fill();
    }

    /** Eksik ya da boş alan belgeyi durdurur (FR-4). */
    private static String value(Map<String, String> record, String key, String recordId) {
        String v = record.get(key);
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException("Kayıt " + recordId + ": eksik alan '" + key + "'");
        }
        return v;
    }

    private static String fill(String text, Map<String, String> record, String recordId) {
        Matcher m = PLACEHOLDER.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            m.appendReplacement(sb, Matcher.quoteReplacement(value(record, m.group(1), recordId)));
        }
        return m.appendTail(sb).toString();
    }

    /** Türkçe karakterler için TTF gömülür; PDF'in standart 14 fontunda ş, ğ, ı, İ yok. */
    private static PDFont font(PDDocument doc, String file) throws IOException {
        try (InputStream in = PdfBoxDocumentGenerator.class.getClassLoader().getResourceAsStream("fonts/" + file)) {
            return PDType0Font.load(doc, in);
        }
    }

    private static float width(PDFont font, float size, String text) throws IOException {
        return font.getStringWidth(text) / 1000 * size;
    }

    /** Sayfada yukarıdan aşağı yazan imleç. */
    private static final class Pen {

        private final PDPageContentStream cs;
        private final float floor;
        private float y;

        Pen(PDPageContentStream cs, float top, float floor) {
            this.cs = cs;
            this.y = top;
            this.floor = floor;
        }

        void write(PDFont font, float size, float x, String text) throws IOException {
            cs.beginText();
            cs.setFont(font, size);
            cs.newLineAtOffset(x, y);
            cs.showText(text);
            cs.endText();
        }

        /** Kelime kelime sarar; sonunda imleç paragrafın altındadır. */
        void paragraph(PDFont font, float size, float x, float maxWidth, String text) throws IOException {
            List<String> lines = new ArrayList<>();
            String line = "";
            for (String word : text.split("\\s+")) {
                String candidate = line.isEmpty() ? word : line + " " + word;
                if (!line.isEmpty() && width(font, size, candidate) > maxWidth) {
                    lines.add(line);
                    line = word;
                } else {
                    line = candidate;
                }
            }
            lines.add(line);
            for (String l : lines) {
                write(font, size, x, l);
                down(size * 1.45f);
            }
        }

        void rule(float x, float length) throws IOException {
            cs.setLineWidth(0.5f);
            cs.moveTo(x, y);
            cs.lineTo(x + length, y);
            cs.stroke();
        }

        // Sınır: tek sayfa; uzun transkript sığmazsa hata verir, gerekirse sayfa kırma eklenir.
        void down(float dy) {
            y -= dy;
            if (y < floor) {
                throw new IllegalArgumentException("Belge tek sayfaya sığmıyor");
            }
        }
    }
}
