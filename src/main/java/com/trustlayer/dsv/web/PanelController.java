package com.trustlayer.dsv.web;

import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.ModelAndView;

import com.trustlayer.dsv.document.DocumentGenerator;
import com.trustlayer.dsv.document.GeneratedDocument;
import com.trustlayer.dsv.institution.InstitutionRegistry;
import com.trustlayer.dsv.signature.PdfSigner;

/**
 * Kurum belge üretim paneli (UC-1, FR-3..FR-6): üret → kurum anahtarıyla imzala → indir.
 * Şimdilik girişsiz; FR-8 girişi geldiğinde kurum, formdan değil oturumdaki kullanıcıdan gelir.
 */
@Controller
class PanelController {

    private final DocumentGenerator generator;
    private final InstitutionRegistry institutions;
    private final PdfSigner signer;

    PanelController(DocumentGenerator generator, InstitutionRegistry institutions, PdfSigner signer) {
        this.generator = generator;
        this.institutions = institutions;
        this.signer = signer;
    }

    @GetMapping("/panel")
    String form() {
        return "panel";
    }

    /** @param belge {@code <kurum>/<tür>}, ör. {@code ornek-hastane/saglik-raporu} */
    @PostMapping("/panel")
    ResponseEntity<byte[]> generate(@RequestParam String belge, @RequestParam String kayitNo) {
        String[] parts = belge.split("/", 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Geçersiz belge türü: " + belge);
        }
        GeneratedDocument doc = generator.generate(parts[0], parts[1], kayitNo.trim());
        byte[] signed = signer.sign(doc.pdf(), institutions.signingIdentity(parts[0]));
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(parts[1] + "-" + doc.documentId() + ".pdf").build().toString())
                .body(signed);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    ModelAndView invalid(IllegalArgumentException e) {
        return new ModelAndView("panel").addObject("hata", e.getMessage());
    }

    /** Ör. anahtar deposu parolası ayarlanmamış: kullanıcıya söylenir, yığın izi gösterilmez. */
    @ExceptionHandler(IllegalStateException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    ModelAndView unavailable(IllegalStateException e) {
        return new ModelAndView("panel").addObject("hata", "Belge şu an imzalanamıyor: " + e.getMessage());
    }
}
