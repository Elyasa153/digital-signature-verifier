package com.trustlayer.dsv.web;

import java.io.IOException;
import java.util.UUID;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import com.trustlayer.dsv.signature.PdfVerifier;

/** Herkese açık doğrulama sayfası (FR-7, FR-9). Yüklenen dosya saklanmaz (K6). */
@Controller
class VerifyController {

    private final PdfVerifier verifier;

    VerifyController(PdfVerifier verifier) {
        this.verifier = verifier;
    }

    @GetMapping("/")
    String home() {
        return "redirect:/dogrula";
    }

    /** QR'dan gelindiyse {@code belge} dolu olur; yalnız uyarı göstermek için kullanılır, güven kaynağı değildir. */
    @GetMapping("/dogrula")
    String form(@RequestParam(required = false) UUID belge, Model model) {
        model.addAttribute("belge", belge);
        return "dogrula";
    }

    @PostMapping("/dogrula")
    String verify(@RequestParam("pdf") MultipartFile pdf, Model model) throws IOException {
        if (pdf.isEmpty()) {
            model.addAttribute("hata", "Dosya seçilmedi.");
        } else {
            model.addAttribute("sonuc", verifier.verify(pdf.getBytes()));
        }
        return "dogrula";
    }
}
