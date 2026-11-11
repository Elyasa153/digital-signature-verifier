package com.trustlayer.dsv.web;

import java.security.Principal;
import java.util.List;

import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.ModelAndView;

import com.trustlayer.dsv.document.DocumentGenerator;
import com.trustlayer.dsv.document.GeneratedDocument;
import com.trustlayer.dsv.common.SigningIdentity;
import com.trustlayer.dsv.institution.InstitutionRegistry;
import com.trustlayer.dsv.ra.RegistrationAuthority;
import com.trustlayer.dsv.signature.PdfSigner;

/**
 * Kurum belge üretim paneli (UC-1, FR-3..FR-6, FR-8): üret → kurum anahtarıyla imzala → indir.
 * Her kurum yalnız kendi kayıtlarını ve belge türlerini görür; başka kurumun kaydına erişim HTTP 403 alır.
 */
@Controller
class PanelController {

    record BelgeSecenegi(String deger, String etiket, String ipucu) {
    }

    private final DocumentGenerator generator;
    private final InstitutionRegistry institutions;
    private final PdfSigner signer;
    private final RegistrationAuthority ra;

    PanelController(DocumentGenerator generator, InstitutionRegistry institutions, PdfSigner signer,
            RegistrationAuthority ra) {
        this.generator = generator;
        this.institutions = institutions;
        this.signer = signer;
        this.ra = ra;
    }

    @GetMapping("/login")
    String loginPage() {
        return "login";
    }

    @GetMapping("/panel")
    String form(Principal principal, Model model) {
        populatePanelModel(principal, model);
        return "panel";
    }

    /** @param belge {@code <kurum>/<tür>}, ör. {@code ornek-hastane/saglik-raporu} */
    @PostMapping("/panel")
    ResponseEntity<byte[]> generate(@RequestParam String belge, @RequestParam String kayitNo, Principal principal) {
        String[] parts = belge.split("/", 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Geçersiz belge türü: " + belge);
        }
        String requestedInstitution = parts[0];
        String currentInstitution = principal.getName();
        if (!currentInstitution.equals(requestedInstitution)) {
            throw new AccessDeniedException("Başka bir kurumun kaydına erişim yetkiniz yok: " + requestedInstitution);
        }
        // İptal edilmiş sertifikayla atılan imza doğrulamada zaten REVOKED olur; hiç üretmemek daha açık.
        if (ra.isRevoked(requestedInstitution)) {
            throw new AccessDeniedException("Kurumun sertifikası iptal edilmiş; belge imzalanamaz.");
        }
        GeneratedDocument doc = generator.generate(requestedInstitution, parts[1], kayitNo.trim());
        SigningIdentity identity = institutions.signingIdentity(requestedInstitution);
        byte[] signed = signer.sign(doc.pdf(), identity);
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(parts[1] + "-" + doc.documentId() + ".pdf").build().toString())
                .body(signed);
    }

    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    ModelAndView forbidden(AccessDeniedException e, Principal principal) {
        ModelAndView mav = new ModelAndView("panel");
        if (principal != null) {
            mav.addObject("kurumId", principal.getName());
            mav.addObject("secenekler", secenekler(principal.getName()));
        }
        return mav.addObject("hata", e.getMessage());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    ModelAndView invalid(IllegalArgumentException e, Principal principal) {
        ModelAndView mav = new ModelAndView("panel");
        if (principal != null) {
            mav.addObject("kurumId", principal.getName());
            mav.addObject("secenekler", secenekler(principal.getName()));
        }
        return mav.addObject("hata", e.getMessage());
    }

    /** Ör. anahtar deposu parolası ayarlanmamış: kullanıcıya söylenir, yığın izi gösterilmez. */
    @ExceptionHandler(IllegalStateException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    ModelAndView unavailable(IllegalStateException e, Principal principal) {
        ModelAndView mav = new ModelAndView("panel");
        if (principal != null) {
            mav.addObject("kurumId", principal.getName());
            mav.addObject("secenekler", secenekler(principal.getName()));
        }
        return mav.addObject("hata", "Belge şu an imzalanamıyor: " + e.getMessage());
    }

    /** Kurumun şablonlarından: örnekler + kendi yükledikleri. */
    private List<BelgeSecenegi> secenekler(String kurumId) {
        return generator.documentTypes(kurumId).stream()
                .map(t -> new BelgeSecenegi(kurumId + "/" + t.id(), t.name(), t.hint())).toList();
    }

    private void populatePanelModel(Principal principal, Model model) {
        if (principal != null) {
            String kurumId = principal.getName();
            model.addAttribute("kurumId", kurumId);
            model.addAttribute("secenekler", secenekler(kurumId));
        }
    }
}
