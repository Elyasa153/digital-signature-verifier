package com.trustlayer.dsv.web;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.util.unit.DataSize;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.ModelAndView;

/**
 * Sınırı aşan yükleme denetleyiciye ulaşmadan reddedilir; kullanıcı boş hata sayfası yerine
 * doğrulama sayfasında anlaşılır bir mesaj görür (HTTP 413).
 */
@ControllerAdvice
class UploadLimitAdvice {

    private final DataSize limit;

    UploadLimitAdvice(@Value("${spring.servlet.multipart.max-file-size}") DataSize limit) {
        this.limit = limit;
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    ModelAndView tooLarge() {
        return new ModelAndView("dogrula",
                Map.of("hata", "Dosya çok büyük: en fazla " + limit.toMegabytes() + " MB yüklenebilir."),
                HttpStatus.PAYLOAD_TOO_LARGE);
    }
}
