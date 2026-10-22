package com.trustlayer.dsv.web;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayInputStream;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class WebTest {

    @TempDir
    static Path runtime;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("dsv.runtime-dir", runtime::toString);
        r.add("dsv.keystore-password", () -> "test-parola");
    }

    @Autowired
    MockMvc mvc;

    @Test
    void verifyPageShowsUploadForm() throws Exception {
        mvc.perform(get("/dogrula"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("name=\"pdf\"")))
                .andExpect(content().string(not(containsString("QR kod belgeyi doğrulamaz"))));
    }

    @Test
    void comingFromQrShowsWarning() throws Exception {
        mvc.perform(get("/dogrula").param("belge", "d509be9a-8166-4ef6-90af-9c4736f7848e"))
                .andExpect(content().string(containsString("QR kod belgeyi doğrulamaz")))
                .andExpect(content().string(containsString("d509be9a-8166-4ef6-90af-9c4736f7848e")));
    }

    @Test
    void notAPdfIsUnsigned() throws Exception {
        var file = new MockMultipartFile("pdf", "x.pdf", "application/pdf", "bu bir pdf değil".getBytes());
        mvc.perform(multipart("/dogrula").file(file))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("elektronik imza bulunamadı")))
                .andExpect(content().string(containsString("data-sonuc=\"kaldi\"")))
                .andExpect(content().string(not(containsString("data-sonuc=\"gecti\""))));
    }

    @Test
    void panelDownloadsGeneratedPdf() throws Exception {
        byte[] pdf = mvc.perform(post("/panel").param("belge", "ornek-hastane/saglik-raporu").param("kayitNo", "SR-2026-0101"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_PDF))
                .andReturn().getResponse().getContentAsByteArray();
        assertEquals("%PDF", new String(Arrays.copyOf(pdf, 4)));
    }

    @Test
    void panelShowsErrorForUnknownRecord() throws Exception {
        mvc.perform(post("/panel").param("belge", "ornek-hastane/saglik-raporu").param("kayitNo", "YOK"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("Kayıt bulunamadı")));
    }

    @Test
    void crlIsPublished() throws Exception {
        byte[] der = mvc.perform(get("/crl"))
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/pkix-crl"))
                .andReturn().getResponse().getContentAsByteArray();
        var crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(der));
        assertEquals("CN=TrustLayer Root CA,O=TrustLayer,C=TR", crl.getIssuerX500Principal().getName());
    }
}
