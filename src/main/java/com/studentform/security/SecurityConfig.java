package com.studentform.security;

import com.studentform.service.CustomAdminCellDetailsService;
import com.studentform.service.CustomAdminDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.*;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.*;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
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

    @Autowired private JwtFilter jwtFilter;
    @Autowired private CustomAdminDetailsService adminUserService;
    @Autowired private CustomAdminCellDetailsService adminCellUserService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth -> auth

                        // ---------------------
                        // PUBLIC ENDPOINTS
                        // ---------------------
                        .requestMatchers(HttpMethod.POST, "/api/students").permitAll()
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/admin/students/views").permitAll()

                        // ---------------------
                        // ADMIN PROTECTED
                        // ---------------------
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")

                        // ---------------------
                        // ADMIN CELL PROTECTED
                        // ---------------------
                        .requestMatchers("/api/admincell/**").hasRole("ADMIN_CELL")

                        // ---------------------
                        // All others must require auth
                        // ---------------------
                        .anyRequest().authenticated()
                )
                .authenticationManager(authenticationManager());

        // CORS must be first
        http.addFilterBefore(corsFilter(), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // AUTH MANAGER
    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(
                adminAuthenticationProvider(),
                adminCellAuthenticationProvider()
        );
    }

    // PASSWORD ENCODER
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // ADMIN
    @Bean
    public DaoAuthenticationProvider adminAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(adminUserService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    // ADMIN_CELL
    @Bean
    public DaoAuthenticationProvider adminCellAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(adminCellUserService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    // GLOBAL CORS — supports Vercel + Render + Localhost
    @Bean
    public CorsFilter corsFilter() {

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);

        // Allowed Origins
        config.addAllowedOriginPattern("http://localhost:3000");
        config.addAllowedOriginPattern("http://localhost:3001");
        config.addAllowedOriginPattern("https://*.vercel.app");
        config.addAllowedOriginPattern("https://*.onrender.com");

        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept", "Origin"));
        config.setExposedHeaders(List.of("Authorization"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return new CorsFilter(source);
    }
}
