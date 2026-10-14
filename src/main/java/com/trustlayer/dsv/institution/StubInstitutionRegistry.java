package com.trustlayer.dsv.institution;

import java.util.List;

import org.springframework.stereotype.Component;

import com.trustlayer.dsv.common.Algorithm;
import com.trustlayer.dsv.common.SigningIdentity;

/** Yer tutucu. İP-5 (Ali Eren) gerçek uygulamayı yazınca bu sınıf silinir. */
@Component
class StubInstitutionRegistry implements InstitutionRegistry {

    private static UnsupportedOperationException todo() {
        return new UnsupportedOperationException("İP-5 (Ali Eren): henüz yazılmadı");
    }

    @Override
    public Institution enroll(String id, String displayName, Algorithm algorithm) {
        throw todo();
    }

    @Override
    public SigningIdentity signingIdentity(String institutionId) {
        throw todo();
    }

    @Override
    public List<Institution> all() {
        throw todo();
    }
}
