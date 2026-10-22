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
 * Gerçek kullanımda kaydı CA yöneticisi yapar.
 * İki kurum iki farklı algoritmayla: deneyde RSA ve ECDSA imzaları yan yana görünsün.
 */
@Component
class DemoInstitutions {

    private static final Logger log = LoggerFactory.getLogger(DemoInstitutions.class);

    private static final Map<String, Institution> DEMO = Map.of(
            "ornek-universite", new Institution("ornek-universite", "Örnek Üniversitesi", Algorithm.RSA_2048),
            "ornek-hastane", new Institution("ornek-hastane", "Örnek Devlet Hastanesi", Algorithm.ECDSA_P256));

    private final InstitutionRegistry registry;
    private final String password;

    DemoInstitutions(InstitutionRegistry registry, @Value("${dsv.keystore-password}") String password) {
        this.registry = registry;
        this.password = password;
    }

    @PostConstruct
    void enrollMissing() {
        if (password.isEmpty()) {
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
    }
}
