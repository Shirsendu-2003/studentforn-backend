package com.studentform.security;

import com.studentform.service.CustomAdminCellDetailsService;
import com.studentform.service.CustomAdminDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired private JwtUtil jwtUtil;
    @Autowired private CustomAdminDetailsService adminService;
    @Autowired private CustomAdminCellDetailsService adminCellService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws ServletException, IOException {

        // Always allow OPTIONS preflight requests
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        final String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            username = jwtUtil.extractUsername(token);
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            String role = jwtUtil.extractRole(token);
            UserDetails userDetails = null;

            if ("ADMIN".equals(role)) {
                userDetails = adminService.loadUserByUsername(username);
            } else if ("ADMIN_CELL".equals(role)) {
                userDetails = adminCellService.loadUserByUsername(username);
            }

            if (userDetails != null && jwtUtil.validateToken(token)) {
                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());

                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }

        chain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {

        String path = request.getRequestURI().replaceAll("//+", "/");

        // Public endpoints — NO authentication required
        return path.startsWith("/api/students")                  // student submission
                || path.startsWith("/api/admin/students/views") // stats public
                || path.startsWith("/api/auth/login")
                || path.startsWith("/api/auth/register")
                || path.startsWith("/api/auth/admincell/login")
                || path.startsWith("/api/auth/admincell/register")
                || path.startsWith("/api/public")
                || "OPTIONS".equalsIgnoreCase(request.getMethod());
    }
}
