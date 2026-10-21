package com.trustlayer.dsv.institution;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import com.trustlayer.dsv.ca.CertificateAuthority;
import com.trustlayer.dsv.common.Algorithm;
import com.trustlayer.dsv.common.Certificates;
import com.trustlayer.dsv.common.SigningIdentity;

@SpringBootTest
class KeystoreInstitutionRegistryTest {

    @TempDir
    static Path runtime;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("dsv.runtime-dir", runtime::toString);
        r.add("dsv.keystore-password", () -> "test-parola");
    }

    @Autowired
    InstitutionRegistry registry;

    @Autowired
    CertificateAuthority ca;

    @Test
    void enrolledInstitutionGetsKeystoreAndChain() throws Exception {
        registry.enroll("deneme-kurum", "Deneme Kurumu", Algorithm.RSA_3072);

        assertTrue(Files.exists(runtime.resolve("institutions/deneme-kurum.p12")));
        SigningIdentity id = registry.signingIdentity("deneme-kurum");
        X509Certificate cert = id.certificate();
        assertEquals("Deneme Kurumu", Certificates.commonName(cert));
        assertEquals(2, id.chain().size());
        assertEquals(ca.rootCertificate(), id.chain().get(1));
        cert.verify(ca.rootCertificate().getPublicKey());
        assertEquals(cert.getPublicKey().getAlgorithm(), id.privateKey().getAlgorithm());
    }

    @Test
    void listsInstitutionsWithAlgorithm() {
        registry.enroll("liste-a", "Liste A", Algorithm.ECDSA_P256);
        List<Institution> all = registry.all();
        assertTrue(all.contains(new Institution("liste-a", "Liste A", Algorithm.ECDSA_P256)), all.toString());
    }

    @Test
    void rejectsDuplicateUnknownAndBadIds() {
        registry.enroll("tekil", "Tekil", Algorithm.ECDSA_P256);
        assertThrows(IllegalArgumentException.class, () -> registry.enroll("tekil", "Tekil", Algorithm.ECDSA_P256));
        assertThrows(IllegalArgumentException.class, () -> registry.signingIdentity("olmayan"));
        assertThrows(IllegalArgumentException.class, () -> registry.signingIdentity("../ca/root"));
    }
}
