package com.trustlayer.dsv.ca;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Component;

/** Yer tutucu. İP-5 (Ali Eren) Bouncy Castle uygulamasını yazınca bu sınıf silinir. */
@Component
class StubCertificateAuthority implements CertificateAuthority {

    private static UnsupportedOperationException todo() {
        return new UnsupportedOperationException("İP-5 (Ali Eren): henüz yazılmadı");
    }

    @Override
    public X509Certificate rootCertificate() {
        throw todo();
    }

    @Override
    public X509Certificate issue(PKCS10CertificationRequest csr, String institutionId) {
        throw todo();
    }

    @Override
    public void revoke(BigInteger serialNumber) {
        throw todo();
    }

    @Override
    public X509CRL currentCrl() {
        throw todo();
    }
}
