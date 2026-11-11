package com.trustlayer.dsv.web;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

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
            .formLogin(form -> form
                .loginPage("/login")
                // Rolüne göre: yönetici /yonetim, kurum /panel.
                .successHandler((req, res, auth) -> res.sendRedirect(req.getContextPath()
                        + (auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_" + AccountStore.ROLE_ADMIN))
                                ? "/yonetim" : "/panel")))
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?cikis")
                .permitAll()
            );
        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
