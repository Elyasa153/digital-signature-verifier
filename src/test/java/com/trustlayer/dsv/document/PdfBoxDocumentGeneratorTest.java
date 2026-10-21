package com.trustlayer.dsv.document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;

/** Repodaki şablonlar ve sentetik kayıtlarla belge üretimi. */
class PdfBoxDocumentGeneratorTest {

    static final String BASE_URL = "http://localhost:8080/dogrula";

    final DocumentGenerator generator =
            new PdfBoxDocumentGenerator(new CsvRecordSource(Path.of("data/records")), BASE_URL);

    /** TS-09: üç belge türü üretilir, Türkçe karakterler bozulmaz, QR belge kimliğini taşır. */
    @ParameterizedTest
    @CsvSource({
            "ornek-universite, transkript,          2021001,      TRANSKRİPT,          Ayşe Yıldırım,  Bilgisayar Mühendisliği Tasarımı",
            "ornek-universite, katilim-sertifikasi, SRT-2026-001, KATILIM SERTİFİKASI, Elif Şahin,     Temel Siber Güvenlik",
            "ornek-hastane,    saglik-raporu,       SR-2026-0103, SAĞLIK RAPORU,       Ömer Faruk Işık, Lisanslı spor"
    })
    void generatesEachDocumentType(String institution, String type, String recordId, String title, String name,
            String detail) throws Exception {
        GeneratedDocument doc = generator.generate(institution, type, recordId);

        try (PDDocument pdf = Loader.loadPDF(doc.pdf())) {
            assertEquals(1, pdf.getNumberOfPages());
            String text = new PDFTextStripper().getText(pdf);
            assertTrue(text.contains(title), text);
            assertTrue(text.contains(name), text);
            assertTrue(text.contains(detail), text);
            assertTrue(text.contains(doc.documentId().toString()), text);
            assertTrue(text.contains("QR kod belgeyi doğrulamaz"), text);

            assertEquals(BASE_URL + "?belge=" + doc.documentId(), readQr(pdf));
        }
    }

    @Test
    void transcriptListsOnlyOwnCoursesAndGpa() throws IOException {
        GeneratedDocument doc = generator.generate("ornek-universite", "transkript", "2021002");
        try (PDDocument pdf = Loader.loadPDF(doc.pdf())) {
            String text = new PDFTextStripper().getText(pdf);
            assertTrue(text.contains("Veri Yapıları"), text);
            assertTrue(text.contains("2,87"), text);
            assertTrue(!text.contains("Algoritma Analizi"), "başka öğrencinin dersi: " + text);
        }
    }

    @Test
    void everyDocumentGetsNewId() {
        var a = generator.generate("ornek-universite", "katilim-sertifikasi", "SRT-2026-002");
        var b = generator.generate("ornek-universite", "katilim-sertifikasi", "SRT-2026-002");
        assertNotEquals(a.documentId(), b.documentId());
    }

    /** TS-10: zorunlu alanı boş kayıt reddedilir, hangi alan olduğu söylenir. */
    @Test
    void recordWithMissingFieldIsRejected(@TempDir Path dir) throws IOException {
        Files.createDirectories(dir.resolve("ornek-hastane"));
        Files.writeString(dir.resolve("ornek-hastane/saglik-raporu.csv"), """
                rapor_no;ad_soyad;dogum_tarihi;muayene_tarihi;rapor_turu;karar;hekim
                SR-1;Can Erdoğan;14.03.1998;02.10.2026;İşe giriş;;Dr. Selin Koç
                """);
        var g = new PdfBoxDocumentGenerator(new CsvRecordSource(dir), BASE_URL);

        var e = assertThrows(IllegalArgumentException.class, () -> g.generate("ornek-hastane", "saglik-raporu", "SR-1"));
        assertTrue(e.getMessage().contains("SR-1") && e.getMessage().contains("karar"), e.getMessage());
    }

    @Test
    void transcriptWithoutCoursesIsRejected(@TempDir Path dir) throws IOException {
        Files.createDirectories(dir.resolve("ornek-universite"));
        Files.writeString(dir.resolve("ornek-universite/transkript.csv"),
                "ogrenci_no;ad_soyad;bolum;giris_yili;gno\n1;Ayşe;Bilgisayar;2021;3,00\n");
        var g = new PdfBoxDocumentGenerator(new CsvRecordSource(dir), BASE_URL);

        assertThrows(IllegalArgumentException.class, () -> g.generate("ornek-universite", "transkript", "1"));
    }

    @Test
    void unknownRecordTemplateOrBadIdIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> generator.generate("ornek-hastane", "saglik-raporu", "YOK"));
        assertThrows(IllegalArgumentException.class, () -> generator.generate("ornek-hastane", "transkript", "2021001"));
        assertThrows(IllegalArgumentException.class, () -> generator.generate("../ornek-hastane", "saglik-raporu", "SR-2026-0101"));
    }

    private static String readQr(PDDocument pdf) throws Exception {
        BufferedImage img = new PDFRenderer(pdf).renderImageWithDPI(0, 150);
        int[] pixels = img.getRGB(0, 0, img.getWidth(), img.getHeight(), null, 0, img.getWidth());
        var bitmap = new BinaryBitmap(new HybridBinarizer(new RGBLuminanceSource(img.getWidth(), img.getHeight(), pixels)));
        return new QRCodeReader().decode(bitmap, Map.of(DecodeHintType.TRY_HARDER, true)).getText();
    }
}
