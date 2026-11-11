package com.trustlayer.dsv.web;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import com.trustlayer.dsv.signature.PdfVerifier;
import com.trustlayer.dsv.signature.Verdict;

/** Kurumun kendi belge türünü yüklemesi: kaydet → panelde görünür → imzalı üretilir; hatalı dosya kaydedilmez. */
@SpringBootTest
@AutoConfigureMockMvc
class SablonYuklemeTest {

    @TempDir
    static Path runtime;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("dsv.runtime-dir", runtime::toString);
        r.add("dsv.keystore-password", () -> "test-parola");
    }

    @Autowired
    MockMvc mvc;

    @Autowired
    PdfVerifier verifier;

    static final RequestPostProcessor HASTANE = user("ornek-hastane").roles("INSTITUTION");

    static final String TEMPLATE = """
            {"name": "Aşı Kartı", "issuer": "Örnek Devlet Hastanesi", "title": "AŞI KARTI",
             "intro": "{ad_soyad} için aşı kaydı.",
             "fields": [{"key": "kart_no", "label": "Kart No"}, {"key": "ad_soyad", "label": "Ad Soyad"},
                        {"key": "asi", "label": "Aşı"}]}""";
    static final String RECORDS = "kart_no;ad_soyad;asi\nAK-1;Zeynep Arı;Tetanoz\nAK-2;Mert Can;Hepatit B\n";

    @Test
    void savedTypeAppearsOnPanelAndProducesValidSignedDocument() throws Exception {
        upload("asi-karti", TEMPLATE, RECORDS, null, "kaydet").andExpect(redirectedUrl("/panel"));

        mvc.perform(get("/panel").with(HASTANE))
                .andExpect(content().string(containsString("ornek-hastane/asi-karti")))
                .andExpect(content().string(containsString("Aşı Kartı")))
                .andExpect(content().string(containsString("Kart No (ör. AK-1)")))
                .andExpect(content().string(containsString("ornek-hastane/saglik-raporu")));
        // Başka kurum görmez.
        mvc.perform(get("/panel").with(user("ornek-universite").roles("INSTITUTION")))
                .andExpect(content().string(not(containsString("asi-karti"))));

        byte[] pdf = mvc.perform(post("/panel").with(csrf()).with(HASTANE)
                        .param("belge", "ornek-hastane/asi-karti").param("kayitNo", "AK-2"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray();
        assertEquals(Verdict.VALID, verifier.verify(pdf).verdict());
    }

    @Test
    void previewReturnsPdfWithoutSaving() throws Exception {
        byte[] pdf = upload("onizleme-turu", TEMPLATE, RECORDS, null, "onizle")
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/pdf"))
                .andReturn().getResponse().getContentAsByteArray();
        assertEquals("%PDF", new String(Arrays.copyOf(pdf, 4)));
        mvc.perform(get("/panel").with(HASTANE)).andExpect(content().string(not(containsString("onizleme-turu"))));
    }

    @Test
    void recordMissingTemplateFieldIsRejected() throws Exception {
        upload("eksik-alan", TEMPLATE, "kart_no;ad_soyad\nAK-1;Zeynep Arı\n", null, "kaydet")
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("eksik alan &#39;asi&#39;")));
        mvc.perform(get("/panel").with(HASTANE)).andExpect(content().string(not(containsString("eksik-alan"))));
    }

    @Test
    void invalidFilesAreRejectedWithReason() throws Exception {
        upload("bozuk-json", "{ bu json değil", RECORDS, null, "kaydet")
                .andExpect(content().string(containsString("JSON&#39;u okunamadı")));
        upload("alansiz", "{\"issuer\": \"X\", \"title\": \"Y\", \"fields\": []}", RECORDS, null, "kaydet")
                .andExpect(content().string(containsString("en az bir fields")));
        upload("../kacis", TEMPLATE, RECORDS, null, "kaydet")
                .andExpect(content().string(containsString("Geçersiz kimlik")));
        upload("bos-kayit", TEMPLATE, "kart_no;ad_soyad;asi\n", null, "kaydet")
                .andExpect(content().string(containsString("en az bir kayıt")));

        // Excel'in ANSI (Windows-1254) CSV'si: "ı" tek bayt 0xFD, UTF-8 değil.
        byte[] ansi = "kart_no;ad_soyad;asi\nAK-1;Arı;Tetanoz\n".getBytes(java.nio.charset.Charset.forName("windows-1254"));
        mvc.perform(multipart("/panel/sablon").file(file("sablon", TEMPLATE.getBytes(StandardCharsets.UTF_8)))
                        .file(file("kayitlar", ansi)).param("tur", "ansi").param("islem", "kaydet").with(csrf()).with(HASTANE))
                .andExpect(content().string(containsString("UTF-8 değil")));
    }

    @Test
    void tooLongDocumentIsRejected() throws Exception {
        String longText = "uzun metin ".repeat(800);
        upload("tasan", TEMPLATE.replace("{ad_soyad} için aşı kaydı.", longText), RECORDS, null, "kaydet")
                .andExpect(content().string(containsString("tek sayfaya sığmıyor")));
    }

    @Test
    void tableTemplateNeedsTableCsv() throws Exception {
        String withTable = TEMPLATE.replace("\"fields\"", "\"table\": {\"source\": \"asi-dozlari\", \"columns\": "
                + "[{\"key\": \"doz\", \"label\": \"Doz\"}, {\"key\": \"tarih\", \"label\": \"Tarih\"}]}, \"fields\"");
        upload("tablolu", withTable, RECORDS, null, "kaydet")
                .andExpect(content().string(containsString("ikinci CSV")));
        upload("tablolu", withTable, RECORDS, "kart_no;doz;tarih\nAK-1;1;01.01.2026\n", "kaydet")
                .andExpect(content().string(containsString("Kayıt AK-2: tablo CSV&#39;sinde satırı yok")));
        upload("tablolu", withTable, RECORDS, "kart_no;doz;tarih\nAK-1;1;01.01.2026\nAK-2;1;02.01.2026\n", "kaydet")
                .andExpect(redirectedUrl("/panel"));
    }

    @Test
    void onlyInstitutionOperatorCanUpload() throws Exception {
        mvc.perform(get("/panel/sablon").with(user("ca-yonetici").roles("CA_ADMIN"))).andExpect(status().isForbidden());
        mvc.perform(get("/panel/sablon")).andExpect(status().is3xxRedirection());
        mvc.perform(multipart("/panel/sablon").file(file("sablon", TEMPLATE.getBytes(StandardCharsets.UTF_8)))
                        .file(file("kayitlar", RECORDS.getBytes(StandardCharsets.UTF_8))).param("tur", "csrfsiz").with(HASTANE))
                .andExpect(status().isForbidden());
    }

    private ResultActions upload(String tur, String template, String records, String table, String islem)
            throws Exception {
        var req = multipart("/panel/sablon")
                .file(file("sablon", template.getBytes(StandardCharsets.UTF_8)))
                .file(file("kayitlar", records.getBytes(StandardCharsets.UTF_8)))
                .param("tur", tur).param("islem", islem).with(csrf()).with(HASTANE);
        if (table != null) {
            req.file(file("tablo", table.getBytes(StandardCharsets.UTF_8)));
        }
        return mvc.perform(req);
    }

    private static MockMultipartFile file(String name, byte[] content) {
        return new MockMultipartFile(name, name + ".dat", "application/octet-stream", content);
    }
}
