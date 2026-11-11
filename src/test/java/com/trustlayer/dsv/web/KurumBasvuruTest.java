package com.trustlayer.dsv.web;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import com.trustlayer.dsv.ra.Application.Status;
import com.trustlayer.dsv.ra.RegistrationAuthority;

/** K11: başvuru → e-posta kodu → CA yöneticisi onayı → operatör girişi; red, iptal, rol ayrımı, parolalar. */
@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class KurumBasvuruTest {

    @TempDir
    static Path runtime;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("dsv.runtime-dir", runtime::toString);
        r.add("dsv.keystore-password", () -> "test-parola");
        r.add("dsv.admin-password", () -> "yonetici-parola");
        r.add("dsv.demo-password", () -> "demo-parola");
    }

    @Autowired
    MockMvc mvc;

    @Autowired
    RegistrationAuthority ra;

    static final RequestPostProcessor ADMIN = user("ca-yonetici").roles("CA_ADMIN");

    @Test
    void appliedConfirmedApprovedInstitutionCanLogIn(CapturedOutput log) throws Exception {
        apply("ornek-belediye", "yetkili@ornek-belediye.example");
        mvc.perform(post("/basvuru/kod").with(csrf()).param("kod", "ornek-belediye")
                        .param("dogrulamaKodu", code(log, "ornek-belediye")))
                .andExpect(content().string(containsString("CA yöneticisinin onayını bekliyor")));

        String password = (String) mvc.perform(post("/yonetim/onay").with(csrf()).with(ADMIN).param("kod", "ornek-belediye"))
                .andExpect(redirectedUrl("/yonetim"))
                .andReturn().getFlashMap().get("yeniParola");
        assertNotNull(password);

        mvc.perform(formLogin("/login").user("ornek-belediye").password(password))
                .andExpect(redirectedUrl("/panel"))
                .andExpect(authenticated().withUsername("ornek-belediye").withRoles("INSTITUTION"));
        mvc.perform(get("/panel").with(user("ornek-belediye").roles("INSTITUTION")))
                .andExpect(content().string(containsString("henüz belge şablonu tanımlanmamış")));
        mvc.perform(get("/yonetim").with(ADMIN))
                .andExpect(content().string(containsString("EPOSTA_DOGRULANDI")))
                .andExpect(content().string(containsString("ONAY")))
                .andExpect(content().string(containsString("Örnek Belediye Kurumu")));
    }

    @Test
    void cannotApproveBeforeEmailIsConfirmed() throws Exception {
        apply("dogrulanmamis", "a@dogrulanmamis.example");
        mvc.perform(post("/yonetim/onay").with(csrf()).with(ADMIN).param("kod", "dogrulanmamis"))
                .andExpect(redirectedUrl("/yonetim"));
        assertEquals(Status.KOD_BEKLIYOR, durum("dogrulanmamis"));
        mvc.perform(formLogin("/login").user("dogrulanmamis").password("herhangi")).andExpect(unauthenticated());
    }

    @Test
    void tooManyWrongCodesCloseTheApplication(CapturedOutput log) throws Exception {
        apply("kaba-kuvvet", "a@kaba-kuvvet.example");
        String real = code(log, "kaba-kuvvet");
        String wrong = real.equals("000000") ? "111111" : "000000";
        for (int i = 0; i < 5; i++) {
            mvc.perform(post("/basvuru/kod").with(csrf()).param("kod", "kaba-kuvvet").param("dogrulamaKodu", wrong));
        }
        mvc.perform(post("/basvuru/kod").with(csrf()).param("kod", "kaba-kuvvet").param("dogrulamaKodu", real))
                .andExpect(content().string(containsString("kod beklemiyor")));
        assertEquals(Status.REDDEDILDI, durum("kaba-kuvvet"));
    }

    @Test
    void duplicateOrReservedIdIsRejected() throws Exception {
        for (String id : new String[] { "ornek-hastane", "ca-yonetici" }) {
            mvc.perform(post("/basvuru").with(csrf()).param("kod", id).param("ad", "Taklit Kurum")
                            .param("algoritma", "RSA_2048").param("yetkili", "X").param("eposta", "x@taklit.example"))
                    .andExpect(content().string(containsString("class=\"hata\"")));
        }
    }

    @Test
    void rejectedApplicationIsAudited() throws Exception {
        apply("reddedilecek", "a@reddedilecek.example");
        mvc.perform(post("/yonetim/red").with(csrf()).with(ADMIN).param("kod", "reddedilecek").param("gerekce", "kimlik doğrulanamadı"));
        assertEquals(Status.REDDEDILDI, durum("reddedilecek"));
        mvc.perform(get("/yonetim").with(ADMIN)).andExpect(content().string(containsString("kimlik doğrulanamadı")));
    }

    /** UC-3 yönetim ekranından: iptal edilen kurum belge üretemez. */
    @Test
    void revokedInstitutionCannotSign(CapturedOutput log) throws Exception {
        apply("iptal-edilecek", "a@iptal-edilecek.example");
        mvc.perform(post("/basvuru/kod").with(csrf()).param("kod", "iptal-edilecek")
                .param("dogrulamaKodu", code(log, "iptal-edilecek")));
        mvc.perform(post("/yonetim/onay").with(csrf()).with(ADMIN).param("kod", "iptal-edilecek"));
        mvc.perform(post("/yonetim/iptal").with(csrf()).with(ADMIN).param("kod", "iptal-edilecek").param("gerekce", "anahtar sızdı"));

        assertTrue(ra.isRevoked("iptal-edilecek"));
        mvc.perform(post("/panel").with(csrf()).with(user("iptal-edilecek").roles("INSTITUTION"))
                        .param("belge", "iptal-edilecek/transkript").param("kayitNo", "1"))
                .andExpect(status().isForbidden())
                .andExpect(content().string(containsString("sertifikası iptal edilmiş")));
        mvc.perform(get("/yonetim").with(ADMIN)).andExpect(content().string(containsString("anahtar sızdı")));
    }

    /** Roller ayrık: yönetici belge üretemez, operatör yönetim ekranına giremez. */
    @Test
    void rolesAreSeparated() throws Exception {
        mvc.perform(post("/panel").with(csrf()).with(ADMIN)
                        .param("belge", "ornek-hastane/saglik-raporu").param("kayitNo", "SR-2026-0101"))
                .andExpect(status().isForbidden());
        mvc.perform(get("/yonetim").with(user("ornek-hastane").roles("INSTITUTION")))
                .andExpect(status().isForbidden());
        mvc.perform(post("/yonetim/iptal").with(csrf()).with(user("ornek-hastane").roles("INSTITUTION"))
                        .param("kod", "ornek-universite"))
                .andExpect(status().isForbidden());
        assertTrue(!ra.isRevoked("ornek-universite"));
    }

    /** Parolalar ortam değişkeninden; eski sabit "kurum123" ve keystore parolası artık giriş açmaz. */
    @Test
    void passwordsComeFromConfigurationOnly() throws Exception {
        mvc.perform(formLogin("/login").user("ornek-hastane").password("demo-parola")).andExpect(authenticated());
        mvc.perform(formLogin("/login").user("ornek-hastane").password("kurum123")).andExpect(unauthenticated());
        mvc.perform(formLogin("/login").user("ornek-hastane").password("test-parola")).andExpect(unauthenticated());
        mvc.perform(formLogin("/login").user("ca-yonetici").password("yonetici-parola"))
                .andExpect(redirectedUrl("/yonetim"));
    }

    @Test
    void applicationFormNeedsCsrfToken() throws Exception {
        mvc.perform(post("/basvuru").param("kod", "csrfsiz").param("ad", "Csrfsiz Kurum").param("algoritma", "RSA_2048")
                        .param("yetkili", "X").param("eposta", "x@csrfsiz.example"))
                .andExpect(status().isForbidden());
        mvc.perform(get("/basvuru")).andExpect(content().string(containsString("name=\"_csrf\"")))
                .andExpect(content().string(not(containsString("class=\"hata\""))));
    }

    private void apply(String id, String email) throws Exception {
        mvc.perform(post("/basvuru").with(csrf()).param("kod", id).param("ad", "Örnek Belediye Kurumu")
                        .param("algoritma", "ECDSA_P256").param("yetkili", "Ayşe Yılmaz").param("eposta", email))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("adresine gönderildi")));
    }

    private static String code(CapturedOutput log, String id) {
        Matcher m = Pattern.compile("doğrulama kodu: (\\d{6}) \\(başvuru " + Pattern.quote(id) + "\\)").matcher(log.getOut());
        assertTrue(m.find(), "kod günlükte yok: " + id);
        return m.group(1);
    }

    private Status durum(String id) {
        return ra.applications().stream().filter(a -> a.id().equals(id)).findFirst().orElseThrow().status();
    }
}
