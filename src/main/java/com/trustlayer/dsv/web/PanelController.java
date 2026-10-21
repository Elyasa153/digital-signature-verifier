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

/**
 * Kurum belge üretim paneli (FR-3..FR-5).
 * Şimdilik girişsiz ve imzasız; FR-8 girişi ve İP-4 imzası bağlanınca {@code sign} burada çağrılır.
 */
@Controller
class PanelController {

    private final DocumentGenerator generator;

    PanelController(DocumentGenerator generator) {
        this.generator = generator;
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
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(parts[1] + "-" + doc.documentId() + ".pdf").build().toString())
                .body(doc.pdf());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    ModelAndView invalid(IllegalArgumentException e) {
        return new ModelAndView("panel").addObject("hata", e.getMessage());
    }
}
