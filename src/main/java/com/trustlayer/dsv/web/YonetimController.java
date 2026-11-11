package com.trustlayer.dsv.web;

import java.security.Principal;
import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.trustlayer.dsv.institution.Institution;
import com.trustlayer.dsv.institution.InstitutionRegistry;
import com.trustlayer.dsv.ra.AuditLog;
import com.trustlayer.dsv.ra.RegistrationAuthority;

/** CA yöneticisi ekranı (K11 adım 3-5): başvuru onayı/reddi, kurum sertifikası iptali, denetim kaydı. */
@Controller
class YonetimController {

    record KurumSatiri(Institution kurum, boolean iptal) {
    }

    private final RegistrationAuthority ra;
    private final InstitutionRegistry registry;
    private final AccountStore accounts;
    private final AuditLog audit;

    YonetimController(RegistrationAuthority ra, InstitutionRegistry registry, AccountStore accounts, AuditLog audit) {
        this.ra = ra;
        this.registry = registry;
        this.accounts = accounts;
        this.audit = audit;
    }

    @GetMapping("/yonetim")
    String page(Model model) {
        model.addAttribute("basvurular", ra.applications());
        List<KurumSatiri> kurumlar = registry.all().stream()
                .filter(i -> !i.id().startsWith("deney-"))
                .map(i -> new KurumSatiri(i, ra.isRevoked(i.id()))).toList();
        model.addAttribute("kurumlar", kurumlar);
        model.addAttribute("denetim", audit.recent(30));
        return "yonetim";
    }

    @PostMapping("/yonetim/onay")
    String approve(@RequestParam String kod, Principal admin, RedirectAttributes flash) {
        try {
            ra.approve(kod, admin.getName());
            // Parola yalnız bu yanıtta görünür; yönetici kuruma bant dışı (telefon, yüz yüze) iletir.
            flash.addFlashAttribute("yeniHesap", kod);
            flash.addFlashAttribute("yeniParola", accounts.createOperator(kod));
        } catch (IllegalArgumentException | IllegalStateException e) {
            flash.addFlashAttribute("hata", e.getMessage());
        }
        return "redirect:/yonetim";
    }

    @PostMapping("/yonetim/red")
    String reject(@RequestParam String kod, @RequestParam(defaultValue = "") String gerekce, Principal admin,
            RedirectAttributes flash) {
        try {
            ra.reject(kod, admin.getName(), gerekce);
            flash.addFlashAttribute("bilgi", "Başvuru reddedildi: " + kod);
        } catch (IllegalArgumentException e) {
            flash.addFlashAttribute("hata", e.getMessage());
        }
        return "redirect:/yonetim";
    }

    @PostMapping("/yonetim/iptal")
    String revoke(@RequestParam String kod, @RequestParam(defaultValue = "") String gerekce, Principal admin,
            RedirectAttributes flash) {
        try {
            ra.revoke(kod, admin.getName(), gerekce);
            flash.addFlashAttribute("bilgi", "Sertifika iptal edildi: " + kod
                    + ". Bu kurumun imzaladığı bütün belgeler artık doğrulamada \"iptal\" görünür.");
        } catch (IllegalArgumentException | IllegalStateException e) {
            flash.addFlashAttribute("hata", e.getMessage());
        }
        return "redirect:/yonetim";
    }
}
