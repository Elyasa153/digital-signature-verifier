package com.trustlayer.dsv.web;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.stringContainsInOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import com.trustlayer.dsv.ca.CertificateAuthority;
import com.trustlayer.dsv.institution.InstitutionRegistry;
import com.trustlayer.dsv.signature.PdfVerifier;
import com.trustlayer.dsv.signature.Verdict;
import com.trustlayer.dsv.signature.VerificationResult;

/**
 * Tamamlanma tanımı: 2 kurum (RSA-2048, ECDSA P-256) × 3 belge türü.
 * Panelden üret + imzala (UC-1) → doğrula VALID (UC-2) → boz → MODIFIED → kurumu iptal et → REVOKED (UC-3).
 */
@SpringBootTest
@AutoConfigureMockMvc
class EndToEndTest {

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

    @Autowired
    InstitutionRegistry registry;

    @Autowired
    CertificateAuthority ca;

    @Test
    void produceSignVerifyTamperRevoke() throws Exception {
        byte[] transcript = panel("ornek-universite/transkript", "2021001");
        byte[] certificate = panel("ornek-universite/katilim-sertifikasi", "SRT-2026-001");
        byte[] report = panel("ornek-hastane/saglik-raporu", "SR-2026-0101");

        // UC-2: üçü de geçerli, imzalayan kendi kurumu.
        assertValid(transcript, "Örnek Üniversitesi");
        assertValid(certificate, "Örnek Üniversitesi");
        assertValid(report, "Örnek Devlet Hastanesi");

        // Doğrulama sayfası aynı sonucu gösterir.
        mvc.perform(multipart("/dogrula").file(new MockMultipartFile("pdf", "b.pdf", "application/pdf", report)))
                .andExpect(content().string(containsString("Belge geçerli")))
                .andExpect(content().string(containsString("Örnek Devlet Hastanesi")))
                .andExpect(content().string(not(containsString("data-sonuc=\"kaldi\""))));

        // Tek bayt değişikliği.
        byte[] tampered = transcript.clone();
        tampered[tampered.length / 3] ^= 0x01;
        assertEquals(Verdict.MODIFIED, verifier.verify(tampered).verdict());
        // Kontrol listesi: imza var geçti, bütünlük kaldı, zincir ve iptal hiç çalışmadı.
        mvc.perform(multipart("/dogrula").file(new MockMultipartFile("pdf", "t.pdf", "application/pdf", tampered)))
                .andExpect(content().string(stringContainsInOrder(
                        "data-sonuc=\"gecti\"", "data-sonuc=\"kaldi\"", "data-sonuc=\"atlandi\"", "data-sonuc=\"atlandi\"")));

        // UC-3: üniversitenin sertifikası iptal → onun bütün belgeleri REVOKED, hastaneninki etkilenmez.
        ca.revoke(registry.signingIdentity("ornek-universite").certificate().getSerialNumber());
        assertEquals(Verdict.REVOKED, verifier.verify(transcript).verdict());
        assertEquals(Verdict.REVOKED, verifier.verify(certificate).verdict());
        assertValid(report, "Örnek Devlet Hastanesi");
    }

    private byte[] panel(String belge, String kayitNo) throws Exception {
        return mvc.perform(post("/panel").param("belge", belge).param("kayitNo", kayitNo))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray();
    }

    private void assertValid(byte[] pdf, String signer) {
        VerificationResult r = verifier.verify(pdf);
        assertEquals(Verdict.VALID, r.verdict(), r.detail());
        assertEquals(signer, r.signer());
    }
}
