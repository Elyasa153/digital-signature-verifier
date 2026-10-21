package com.trustlayer.dsv.web;

import java.security.cert.CRLException;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.trustlayer.dsv.ca.CertificateAuthority;

/** Kurum sertifikalarındaki CRL Distribution Point adresi; Adobe gibi dış okuyucular iptali buradan görür. */
@RestController
class CrlController {

    private final CertificateAuthority ca;

    CrlController(CertificateAuthority ca) {
        this.ca = ca;
    }

    @GetMapping("/crl")
    ResponseEntity<byte[]> crl() throws CRLException {
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/pkix-crl"))
                .body(ca.currentCrl().getEncoded());
    }
}
