package com.trustlayer.dsv.common;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

public final class Certificates {

    private Certificates() {
    }

    /** Sertifika sahibinin adı (CN). İmzalayan adı koda gömülmez, buradan okunur. */
    public static String commonName(X509Certificate cert) {
        RDN[] cn = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded()).getRDNs(BCStyle.CN);
        return cn.length == 0 ? cert.getSubjectX500Principal().getName() : IETFUtils.valueToString(cn[0].getFirst().getValue());
    }
}
