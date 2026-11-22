package com.trustlayer.dsv.web;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * FR-8, FR-9 ve K11 güvenlik yapılandırması:
 * - /dogrula, /crl ve /basvuru herkese açıktır, hesap gerektirmez (FR-9, K11 adım 1-2).
 * - /panel yalnız kurum operatörüne açık (belge üretir); /yonetim yalnız CA yöneticisine (onay, red, iptal).
 *   CA yöneticisi belge üretemez, operatör kurum ekleyemez. Girişsiz istekler /login sayfasına yönlendirilir.
 * - Oturumla yapılan her POST CSRF belirteci ister: başka bir site, girişli kurumun tarayıcısına belge ürettiremez.
 *   /dogrula hariç: oturumsuz, kimse adına işlem yapmaz.
 */
@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.ignoringRequestMatchers("/dogrula"))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/dogrula", "/crl", "/style.css", "/login", "/error").permitAll()
                .requestMatchers("/basvuru", "/basvuru/**").permitAll()
                .requestMatchers("/panel", "/panel/**").hasRole(AccountStore.ROLE_INSTITUTION)
                .requestMatchers("/yonetim", "/yonetim/**").hasRole(AccountStore.ROLE_ADMIN)
                .anyRequest().permitAll()
            )
            // Rolün açamadığı sayfada ham 403 yerine açıklama ve kendi sayfasına dönüş linki.
            .exceptionHandling(e -> e.accessDeniedPage("/yetkisiz"))
            .formLogin(form -> form
                .loginPage("/login")
                // Girişe bir sayfadan düşüldüyse oraya döner; yoksa rolüne göre: yönetici /yonetim, kurum /panel.
                .successHandler(new SavedRequestAwareAuthenticationSuccessHandler() {
                    @Override
                    protected String determineTargetUrl(HttpServletRequest req, HttpServletResponse res, Authentication auth) {
                        return homePage(auth);
                    }
                })
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?cikis")
                .permitAll()
            );
        return http.build();
    }

    /** Girişli kullanıcının ana sayfası: CA yöneticisi /yonetim, kurum /panel. */
    static String homePage(Authentication auth) {
        boolean admin = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_" + AccountStore.ROLE_ADMIN));
        return admin ? "/yonetim" : "/panel";
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
