package com.trustlayer.dsv.signature;

import org.springframework.stereotype.Component;

import com.trustlayer.dsv.common.SigningIdentity;

/** Yer tutucu. İP-4 (Elyasa) PDFBox + Bouncy Castle uygulamasını yazınca bu sınıf silinir. */
@Component
class StubPdfSignature implements PdfSigner, PdfVerifier {

    @Override
    public byte[] sign(byte[] pdf, SigningIdentity identity) {
        throw new UnsupportedOperationException("İP-4 (Elyasa): henüz yazılmadı");
    }

    /** Web tarafı çalışabilsin diye sabit sonuç döner. */
    @Override
    public VerificationResult verify(byte[] pdf) {
        return new VerificationResult(Verdict.UNSIGNED, null, null, "Doğrulama modülü henüz yazılmadı (İP-4)");
    }
}
