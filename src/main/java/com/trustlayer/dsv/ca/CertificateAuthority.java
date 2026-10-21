package com.trustlayer.dsv.ca;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * Kök sertifika otoritesi (İP-5). Kurumların gizli anahtarını hiç görmez:
 * yalnızca CSR alır, imzalı sertifika döndürür.
 */
public interface CertificateAuthority {

    /** Doğrulayıcının tek güven kökü. */
    X509Certificate rootCertificate();

    /**
     * CSR'daki açık anahtar için kök CA imzalı kurum sertifikası üretir (FR-1).
     * CSR kendi gizli anahtarıyla imzalı olmalı; değilse reddedilir.
     */
    X509Certificate issue(PKCS10CertificationRequest csr, String institutionId);

    /** Sertifikayı iptal eder; bir sonraki {@link #currentCrl()} bu seriyi içerir (FR-2). */
    void revoke(BigInteger serialNumber);

    /** Kök CA imzalı güncel iptal listesi. */
    X509CRL currentCrl();
}
