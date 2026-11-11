package com.trustlayer.dsv.web;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.trustlayer.dsv.common.Algorithm;
import com.trustlayer.dsv.institution.Institution;
import com.trustlayer.dsv.institution.InstitutionRegistry;

/**
 * Panelin örnek kurumları ilk açılışta, sunucu istek almaya başlamadan kaydedilir (Akış A).
 * Gerçek kullanımda kurum /basvuru üzerinden başvurur, CA yöneticisi onaylar (K11); bu sınıf o akışı atlayan demo kısayolu.
 * İki kurum iki farklı algoritmayla: deneyde RSA ve ECDSA imzaları yan yana görünsün.
 * Operatör parolası DSV_DEMO_PASSWORD'den; boşsa her açılışta rastgele üretilip günlüğe yazılır.
 */
@Component
class DemoInstitutions {

    private static final Logger log = LoggerFactory.getLogger(DemoInstitutions.class);

    private static final Map<String, Institution> DEMO = Map.of(
            "ornek-universite", new Institution("ornek-universite", "Örnek Üniversitesi", Algorithm.RSA_2048),
            "ornek-hastane", new Institution("ornek-hastane", "Örnek Devlet Hastanesi", Algorithm.ECDSA_P256));

    private final InstitutionRegistry registry;
    private final AccountStore accounts;
    private final String keystorePassword;
    private final String demoPassword;

    DemoInstitutions(InstitutionRegistry registry, AccountStore accounts,
            @Value("${dsv.keystore-password}") String keystorePassword,
            @Value("${dsv.demo-password:}") String demoPassword) {
        this.registry = registry;
        this.accounts = accounts;
        this.keystorePassword = keystorePassword;
        this.demoPassword = demoPassword;
    }

    @PostConstruct
    void enrollMissing() {
        if (keystorePassword.isEmpty()) {
            log.warn("DSV_KEYSTORE_PASSWORD ayarlanmamış: kurumlar kaydedilmedi, panel belge imzalayamaz.");
            return;
        }
        Set<String> enrolled = registry.all().stream().map(Institution::id).collect(Collectors.toSet());
        for (Institution i : DEMO.values()) {
            if (!enrolled.contains(i.id())) {
                registry.enroll(i.id(), i.displayName(), i.algorithm());
                log.info("Örnek kurum kaydedildi: {} ({})", i.id(), i.algorithm());
            }
        }
        String password = demoPassword.isEmpty() ? accounts.newPassword() : demoPassword;
        DEMO.keySet().forEach(id -> accounts.setPassword(id, password));
        if (demoPassword.isEmpty()) {
            log.warn("DSV_DEMO_PASSWORD ayarlanmamış; bu çalıştırma için örnek kurum parolası: {}", password);
        }
    }
}
