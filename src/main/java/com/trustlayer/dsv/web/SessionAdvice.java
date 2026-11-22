package com.trustlayer.dsv.web;

import java.security.Principal;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

/** Her sayfanın menüsü için girişli kullanıcının ana sayfası; girişsizse null. */
@ControllerAdvice
class SessionAdvice {

    @ModelAttribute("anaSayfa")
    String homePage(Principal principal) {
        return principal instanceof Authentication auth ? SecurityConfig.homePage(auth) : null;
    }
}
