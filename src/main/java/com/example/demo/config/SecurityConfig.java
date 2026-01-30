package com.example.demo.config;

import com.example.demo.security.JwtAuthFilter;
import com.example.demo.security.JwtService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

@Configuration
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;

    public SecurityConfig(UserDetailsService userDetailsService,
                          JwtService jwtService) {
        this.userDetailsService = userDetailsService;
        this.jwtService = jwtService;
    }

    // 🔐 Password hashing
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    // 🔐 Authentication provider
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider =
                new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public JwtAuthFilter jwtAuthFilter() {
        return new JwtAuthFilter(jwtService, userDetailsService);
    }

    // 🛡️ MAIN SECURITY CONFIG WITH HEADERS AND SECURE COOKIES
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http)
            throws Exception {

        http
                // ---------------- CSRF ----------------
                .csrf(csrf -> csrf
                        .csrfTokenRepository(
                                CookieCsrfTokenRepository
                                        .withHttpOnlyFalse()) // CSRF token accessible by JS if needed
                        .ignoringRequestMatchers(
                                "/login", "/auth/**", "/api/**")
                )

                // ---------------- SECURITY HEADERS ----------------
                .headers(headers -> headers
                        .contentTypeOptions(content -> {}) // X-Content-Type-Options: nosniff
                        .frameOptions(frame -> frame.deny()) // X-Frame-Options: DENY
                        .referrerPolicy(ref -> ref.policy(
                                ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'self'; " +
                                        "style-src 'self' https://cdn.jsdelivr.net; " +
                                        "script-src 'self'; " +
                                        "img-src 'self' data:"))
                )

                // ---------------- AUTHORIZATION ----------------
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/", "/login", "/register",
                                "/css/**", "/js/**",
                                "/auth/**", "/hello")
                        .permitAll()
                        .requestMatchers(
                                "/notes", "/notes/**",
                                "/api/notes/**")
                        .authenticated()
                        .anyRequest().authenticated()
                )

                // ---------------- FORM LOGIN ----------------
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/notes", true)
                        .permitAll()
                )

                // ---------------- LOGOUT ----------------
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .invalidateHttpSession(true)   // session destroy
                        .deleteCookies("JSESSIONID")   // cookie cleanup
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                )

                // ---------------- SESSION MANAGEMENT ----------------
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                )

                // ---------------- JWT FILTER ----------------
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(
                        jwtAuthFilter(),
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
