package com.trustlayer.dsv.web;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.Principal;

import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.trustlayer.dsv.document.TemplateUploads;
import com.trustlayer.dsv.ra.AuditLog;

/**
 * Kurum operatörünün kendi belge türünü yüklemesi (K11 sonrası: onaylanan kurumun ilk şablonu dahil).
 * "Önizle" imzasız ilk kaydı yeni sekmede açar, hiçbir şey kaydetmez; "Kaydet" her kaydı deneyip kaydeder.
 */
@Controller
class SablonController {

    private final TemplateUploads uploads;
    private final AuditLog audit;

    SablonController(TemplateUploads uploads, AuditLog audit) {
        this.uploads = uploads;
        this.audit = audit;
    }

    @GetMapping("/panel/sablon")
    String form() {
        return "sablon";
    }

    @PostMapping("/panel/sablon")
    Object upload(@RequestParam String tur, @RequestParam MultipartFile sablon, @RequestParam MultipartFile kayitlar,
            @RequestParam(required = false) MultipartFile tablo, @RequestParam(defaultValue = "kaydet") String islem,
            Principal principal, RedirectAttributes flash) {
        String kurum = principal.getName();
        String type = tur.trim();
        byte[] table = tablo == null ? null : bytes(tablo);
        if ("onizle".equals(islem)) {
            byte[] pdf = uploads.preview(kurum, type, bytes(sablon), bytes(kayitlar), table);
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_PDF)
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            ContentDisposition.inline().filename("onizleme-" + type + ".pdf").build().toString())
                    .body(pdf);
        }
        int count = uploads.save(kurum, type, bytes(sablon), bytes(kayitlar), table);
        audit.record(kurum, "SABLON_YUKLEME", kurum, type + ", " + count + " kayıt");
        flash.addFlashAttribute("bilgi", "\"" + type + "\" belge türü kaydedildi (" + count + " kayıt).");
        return "redirect:/panel";
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    ModelAndView invalid(IllegalArgumentException e) {
        return new ModelAndView("sablon").addObject("hata", e.getMessage());
    }

    private static byte[] bytes(MultipartFile file) {
        try {
            return file.getBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
