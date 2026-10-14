package com.trustlayer.dsv.institution;

import java.util.List;

import com.trustlayer.dsv.common.Algorithm;
import com.trustlayer.dsv.common.SigningIdentity;

/**
 * Kurum kaydı ve kurum anahtarlarının saklanması (İP-5).
 * Anahtar burada üretilir, CA'ya yalnızca CSR gider.
 */
public interface InstitutionRegistry {

    /** Anahtar çifti üret → CSR → {@code CertificateAuthority.issue} → parolalı PKCS#12'ye yaz. */
    Institution enroll(String id, String displayName, Algorithm algorithm);

    /** Panelde imza atmak için kurumun anahtarı ve zinciri. */
    SigningIdentity signingIdentity(String institutionId);

    List<Institution> all();
}
