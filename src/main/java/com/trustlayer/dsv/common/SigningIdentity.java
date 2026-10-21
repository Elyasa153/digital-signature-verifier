package com.trustlayer.dsv.common;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Bir kurumun imza atmak için ihtiyaç duyduğu her şey.
 *
 * @param chain kurum sertifikası başta, kök CA sonda; PDF'e olduğu gibi gömülür
 */
public record SigningIdentity(String institutionId, PrivateKey privateKey, List<X509Certificate> chain) {

    public SigningIdentity {
        if (chain.isEmpty()){
            throw new IllegalArgumentException("chain boş olamaz.");
        }
        chain = List.copyOf(chain);
    }

    public X509Certificate certificate() {
        return chain.get(0);
    }
}
