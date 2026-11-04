package com.trustlayer.dsv.web;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

import com.trustlayer.dsv.signature.PdfVerifier;
import com.trustlayer.dsv.signature.Verdict;
import com.trustlayer.dsv.signature.VerificationResult;

import jakarta.validation.constraints.AssertTrue;

@SpringBootTest
@AutoConfigureMockMvc
class TamperSuiteTest {
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
	    private final StringBuilder tablo = new StringBuilder(        
	            "| Dosya | Beklenen | Doğrulayıcı | /dogrula |\n|---|---|---|---|\n");
	    
	    @Test
	    void tamperSuite()throws Exception {
	    Path klasor=Files.createDirectories(Path.of("target","tamper-suite"));
	    byte[] transcript = panel("ornek-universite/transkript", "2021001");
        byte[] certificate = panel("ornek-universite/katilim-sertifikasi", "SRT-2026-001");
        byte[] report = panel("ornek-hastane/saglik-raporu", "SR-2026-0101");

        // UC-2: üçü de geçerli, imzalayan kendi kurumu.
        assertValid(transcript, "Örnek Üniversitesi");
        assertValid(certificate, "Örnek Üniversitesi");
        assertValid(report, "Örnek Devlet Hastanesi");
        
        //sağlamlar
        Files.write(klasor.resolve("saglik-raporu-saglam.pdf"),report);
        Files.write(klasor.resolve("transkript-saglam.pdf"),transcript);
        Files.write(klasor.resolve("katilim-sertifikasi-saglam.pdf"),certificate);
        
        //tek bayt bozuklukları
        //sağlık raporu
        bozukKaydet(klasor, "saglik-raporu-tekbayt.pdf", tekBayt(report));
        //transkript
        bozukKaydet(klasor, "transkript-tekbayt.pdf", tekBayt(transcript));
        //katilim sertifikasi
        bozukKaydet(klasor, "katilim-sertifikasi-tekbayt.pdf", tekBayt(certificate));
        
        //yeni içerik bozuklukları

        byte[] bozuk = icerikEkle(report);
        bozukKaydet(klasor, "saglik-raporu-icerikekleme.pdf", bozuk);
        try (PDDocument d = Loader.loadPDF(bozuk)) {
            assertTrue(new PDFTextStripper().getText(d).contains("SAHTE"));
        }
        bozuk = icerikEkle(transcript);
        bozukKaydet(klasor, "transkript-icerikekleme.pdf", bozuk);
        try (PDDocument d = Loader.loadPDF(bozuk)) {
            assertTrue(new PDFTextStripper().getText(d).contains("SAHTE"));
        }
        bozuk = icerikEkle(certificate);
        bozukKaydet(klasor, "katilim-sertifikasi-icerikekleme.pdf", bozuk);
        try (PDDocument d = Loader.loadPDF(bozuk)) {
            assertTrue(new PDFTextStripper().getText(d).contains("SAHTE"));
        }
        
        //sayfa silme bozuklukları
        bozuk = sayfaSil(report);
        bozukKaydet(klasor, "saglik-raporu-sayfasilme.pdf", bozuk);
        try (PDDocument d = Loader.loadPDF(bozuk)) {
            assertEquals(0, d.getNumberOfPages());
        }
        bozuk = sayfaSil(transcript);
        bozukKaydet(klasor, "transkript-sayfasilme.pdf", bozuk);
        try (PDDocument d = Loader.loadPDF(bozuk)) {
            assertEquals(0, d.getNumberOfPages());
        }
        bozuk = sayfaSil(certificate);
        bozukKaydet(klasor, "katilim-sertifikasi-sayfasilme.pdf", bozuk);
        try (PDDocument d = Loader.loadPDF(bozuk)) {
            assertEquals(0, d.getNumberOfPages());
        }
        
        //imza bozma bozuklukları
        bozukKaydet(klasor, "saglik-raporu-imzaalani.pdf", imzaBoz(report));
        bozukKaydet(klasor, "transkript-imzaalani.pdf", imzaBoz(transcript));
        bozukKaydet(klasor, "katilim-sertifikasi-imzaalani.pdf", imzaBoz(certificate));
        
        //tabloyu hazırla
        Files.writeString(klasor.resolve("sonuclar.md"), tablo.toString());
	    }
	    
	    private void bozukKaydet(Path klasor, String ad, byte[] bozuk) throws Exception {
	        Files.write(klasor.resolve(ad), bozuk);
	        assertEquals(Verdict.MODIFIED, verifier.verify(bozuk).verdict(), ad);
	        mvc.perform(multipart("/dogrula").file(new MockMultipartFile("pdf", ad, "application/pdf", bozuk)))
	        .andExpect(content().string(containsString("Belge imzadan sonra değiştirilmiş")));
	        Verdict sonuc = verifier.verify(bozuk).verdict();
	        tablo.append("| " + ad + " | MODIFIED | " + sonuc + " | Belge imzadan sonra değiştirilmiş |\n");
	        assertEquals(Verdict.MODIFIED, sonuc, ad);
	    }
	    
	   
	    private byte[] panel(String belge, String kayitNo) throws Exception {
	        return mvc.perform(post("/panel").param("belge", belge).param("kayitNo", kayitNo))
	                .andExpect(status().isOk())
	                .andReturn().getResponse().getContentAsByteArray();
	    }
	    //içeriğin değişip değişmediğini kontrol eder
	    private byte[]tekBayt(byte[]signed){
	    	byte[] tampered = signed.clone();
	    	int i = indexOf(signed, "stream".getBytes(StandardCharsets.US_ASCII));
	    	int j = indexOf(signed,"endstream".getBytes(StandardCharsets.US_ASCII));
	    	int changedByte=(i+j)/2;
	    	tampered[changedByte] ^= 0x01;
	    	return tampered;
	    }
	    
	    private byte[]icerikEkle(byte[]signed)throws Exception{
	    	try(PDDocument doc=Loader.loadPDF(signed)){
	    		PDPage sayfa=doc.getPage(0);
	    		try(PDPageContentStream cs=new PDPageContentStream(doc,sayfa,PDPageContentStream.AppendMode.APPEND,true,true)){
	    			cs.beginText();
	    			cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD),48);
	    			cs.newLineAtOffset(150, 400);
	    			cs.showText("SAHTE YAZI");
	    			cs.endText();
	    		}
	    		sayfa.getCOSObject().setNeedToBeUpdated(true);
	    		ByteArrayOutputStream out=new ByteArrayOutputStream();
	    		doc.saveIncremental(out);
	    		return out.toByteArray();
	    	}
	    }
	    
	    private byte[] sayfaSil(byte[] signed) throws Exception{
	    	try(PDDocument doc=Loader.loadPDF(signed)) {
	    		doc.removePage(0);
	    		doc.getPages().getCOSObject().setNeedToBeUpdated(true);
	    		ByteArrayOutputStream out=new ByteArrayOutputStream();
	    		doc.saveIncremental(out);
	    		return out.toByteArray();
	    	}
	    }
	    
	    private byte[] imzaBoz(byte[] signed) throws Exception{
	    	int[] range;
	    	try (PDDocument doc = Loader.loadPDF(signed)) {
	    	    range = doc.getSignatureDictionaries().get(0).getByteRange();
	    	    byte[] tampered = signed.clone();
	    	    int i = range[1] + 200;
	    	    tampered[i] = (byte) (tampered[i] == '0' ? '1' : '0');
	    	    assertTrue(i<range[2]); //imza gerçekten orada mı ?
	    	    return tampered;
	    	}
	    }
	    
	    
	    
	    
	    static int indexOf(byte[] data, byte[] pattern) {
	        outer:
	        for (int i = 0; i <= data.length - pattern.length; i++) {
	            for (int j = 0; j < pattern.length; j++) {
	                if (data[i + j] != pattern[j]) {
	                    continue outer;
	                }
	            }
	            return i;
	        }
	        throw new IllegalArgumentException("bulunamadı");
	    }
	    
	    private void assertValid(byte[] pdf, String signer) {
	        VerificationResult r = verifier.verify(pdf);
	        assertEquals(Verdict.VALID, r.verdict(), r.detail());
	        assertEquals(signer, r.signer());
	    }
}
