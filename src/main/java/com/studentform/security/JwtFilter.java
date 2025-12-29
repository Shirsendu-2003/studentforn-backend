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
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private CustomAdminDetailsService customAdminDetailsService;
    @Autowired
    private CustomAdminCellDetailsService customAdminCellDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");

        String username = null;
        String jwt = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7);
            username = jwtUtil.extractUsername(jwt);
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            String role = jwtUtil.extractRole(jwt);
            UserDetails userDetails = null;

            if ("ADMIN".equals(role)) {
                userDetails = this.customAdminDetailsService.loadUserByUsername(username);
            } else if ("ADMIN_CELL".equals(role)) {
                userDetails = this.customAdminCellDetailsService.loadUserByUsername(username);
            }

            if (userDetails != null && jwtUtil.validateToken(jwt)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        chain.doFilter(request, response);
    }

   @Override
protected boolean shouldNotFilter(HttpServletRequest request) {

    // ✅ Skip JWT for CORS preflight
    if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
        return true;
    }

    String path = request.getRequestURI();

    // Public endpoints
    if (path.startsWith("/api/students")) return true;
    if (path.startsWith("/api/auth/")) return true;
    if (path.equals("/api/admin/students/views")) return true;

    return false;
}


}
