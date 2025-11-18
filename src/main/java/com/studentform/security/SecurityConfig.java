package com.studentform.security;

import com.studentform.service.CustomAdminDetailsService;
import com.studentform.service.CustomAdminCellDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.*;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.*;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.*;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private JwtFilter jwtFilter;

    @Autowired
    private CustomAdminCellDetailsService adminCellUserDetailsService;

    @Autowired
    private CustomAdminDetailsService adminUserDetailsService;

    // ----------------------------------------------
    // 🔥 MAIN SECURITY CONFIG
    // ----------------------------------------------
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth -> auth

                        // -----------------------------------------
                        // 🔓 PUBLIC ENDPOINTS (NO TOKEN REQUIRED)
                        // -----------------------------------------
                        .requestMatchers(HttpMethod.POST, "/api/students").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/admin/students/views").permitAll()

                        .requestMatchers(HttpMethod.POST, "/api/auth/login", "/api/auth/register").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/admincell/login", "/api/auth/admincell/register").permitAll()

                        // -----------------------------------------
                        // 🔐 PROTECTED (ADMIN)
                        // -----------------------------------------
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")

                        // -----------------------------------------
                        // 🔐 PROTECTED (ADMIN_CELL)
                        // -----------------------------------------
                        .requestMatchers("/api/admincell/**").hasRole("ADMIN_CELL")

                        // -----------------------------------------
                        // 🔒 ALL OTHER REQUESTS REQUIRE AUTH
                        // -----------------------------------------
                        .anyRequest().authenticated()
                )

                .authenticationManager(authenticationManager());

        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // ----------------------------------------------
    // 🔥 AUTH MANAGER
    // ----------------------------------------------
    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(
                adminAuthenticationProvider(),
                adminCellAuthenticationProvider()
        );
    }

    // ----------------------------------------------
    // 🔥 PASSWORD ENCODER
    // ----------------------------------------------
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // ----------------------------------------------
    // 🔥 AUTH PROVIDERS
    // ----------------------------------------------
    @Bean
    public DaoAuthenticationProvider adminAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(adminUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public DaoAuthenticationProvider adminCellAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(adminCellUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    // ----------------------------------------------
    // 🔥 CORS CONFIG FOR VERCEL + RENDER + LOCALHOST
    // ----------------------------------------------
    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowCredentials(true);

        // Localhost
        config.addAllowedOriginPattern("http://localhost:3000");
        config.addAllowedOriginPattern("http://localhost:3001");

        // Vercel (wildcard support)
        config.addAllowedOriginPattern("https://*.vercel.app");

        // Render frontend (if used)
        config.addAllowedOriginPattern("https://*.onrender.com");

        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return new CorsFilter(source);
    }

}
