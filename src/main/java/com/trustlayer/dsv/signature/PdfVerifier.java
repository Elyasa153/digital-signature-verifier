package com.trustlayer.dsv.signature;

/** İmzalı PDF'in doğrulanması (İP-4, FR-7). Güven kökü ve CRL {@code CertificateAuthority}'den okunur. */
public interface PdfVerifier {

    /** Hiçbir girdide istisna fırlatmaz; bozuk ya da imzasız dosya da bir {@link Verdict} alır. */
    VerificationResult verify(byte[] pdf);
}
