package com.trustlayer.dsv.signature;

import com.trustlayer.dsv.common.SigningIdentity;

/** PDF'e PAdES imza gömer (İP-4, FR-6). */
public interface PdfSigner {

    /** Sertifika zinciri imzayla birlikte gömülür; doğrulayıcının ayrıca sertifika istemesi gerekmez. */
    byte[] sign(byte[] pdf, SigningIdentity identity);
}
