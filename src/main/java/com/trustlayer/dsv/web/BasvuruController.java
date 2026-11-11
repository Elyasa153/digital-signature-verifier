package com.trustlayer.dsv.web;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import com.trustlayer.dsv.common.Algorithm;
import com.trustlayer.dsv.ra.Application;
import com.trustlayer.dsv.ra.RegistrationAuthority;

/** Kurum başvurusu (K11 adım 1-2): hesapsız form → e-posta kodu → CA yöneticisi onayı bekler. */
@Controller
class BasvuruController {

    private final RegistrationAuthority ra;
    private final AccountStore accounts;

    BasvuruController(RegistrationAuthority ra, AccountStore accounts) {
        this.ra = ra;
        this.accounts = accounts;
    }

    @GetMapping("/basvuru")
    String form(Model model) {
        model.addAttribute("algoritmalar", Algorithm.values());
        return "basvuru";
    }

    @PostMapping("/basvuru")
    String apply(@RequestParam String kod, @RequestParam String ad, @RequestParam(required = false) Algorithm algoritma,
            @RequestParam String yetkili, @RequestParam String eposta, Model model) {
        model.addAttribute("algoritmalar", Algorithm.values());
        try {
            if (accounts.exists(kod.trim())) {
                throw new IllegalArgumentException("Bu kısa kod kullanılamaz: " + kod.trim());
            }
            Application app = ra.apply(kod, ad, algoritma, yetkili, eposta);
            model.addAttribute("basvuru", app);
        } catch (IllegalArgumentException e) {
            model.addAttribute("hata", e.getMessage());
            model.addAttribute("girdi", new Girdi(kod, ad, algoritma, yetkili, eposta));
        }
        return "basvuru";
    }

    @PostMapping("/basvuru/kod")
    String confirm(@RequestParam String kod, @RequestParam String dogrulamaKodu, Model model) {
        model.addAttribute("algoritmalar", Algorithm.values());
        try {
            model.addAttribute("onayBekliyor", ra.confirm(kod, dogrulamaKodu));
        } catch (IllegalArgumentException e) {
            model.addAttribute("hata", e.getMessage());
            model.addAttribute("kodBekleyen", kod);
        }
        return "basvuru";
    }

    /** Hatalı gönderimde form dolu geri gelsin. */
    record Girdi(String kod, String ad, Algorithm algoritma, String yetkili, String eposta) {
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    String badAlgorithm(Model model) {
        model.addAttribute("algoritmalar", Algorithm.values());
        model.addAttribute("hata", "Geçersiz algoritma.");
        return "basvuru";
    }
}
