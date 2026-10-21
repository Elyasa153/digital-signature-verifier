package com.trustlayer.dsv.institution;

import com.trustlayer.dsv.common.Algorithm;

/** Belge veren kurum. {@code id} dosya ve URL adlarında kullanılır: küçük harf, rakam, tire. */
public record Institution(String id, String displayName, Algorithm algorithm) {
}
