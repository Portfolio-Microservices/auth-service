package com.portfolio.auth.security;

import java.io.IOException;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.portfolio.auth.service.TokenBlacklistService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

	@Autowired
	private JwtTokenProvider tokenProvider;

	@Autowired
	private TokenBlacklistService tokenBlacklistService;

	private static final String BEARER_PREFIX = "Bearer ";

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			String jwt = extractJwtFromRequest(request);

			if (StringUtils.hasText(jwt) && tokenBlacklistService.isTokenBlacklisted(jwt)) {
				System.err.println("Token is blacklisted (user logged out)");
				filterChain.doFilter(request, response);
				return;
			}

			if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
				String username = tokenProvider.getUsernameFromToken(jwt);
				Long userId = tokenProvider.getUserIdFromToken(jwt);
				String role = tokenProvider.getRoleFromToken(jwt);
				String type = tokenProvider.getTokenType(jwt);

				if (!"ACCESS".equals(type)) {
					throw new RuntimeException("Invalid token type for authentication");
				}
				if (!role.startsWith("ROLE_")) {
					throw new RuntimeException("Invalid role format in JWT");
				}

				SimpleGrantedAuthority authority = new SimpleGrantedAuthority(role);
				UserDetails userDetails = new UserPrincipal(userId, null, username, null,
						Collections.singletonList(authority));

				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		} catch (Exception ex) {
			System.err.println("Could not set user authentication in security context: " + ex.getMessage());
		}

		filterChain.doFilter(request, response);
	}

	private String extractJwtFromRequest(HttpServletRequest request) {
		String bearerToken = request.getHeader("Authorization");

		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
			return bearerToken.substring(BEARER_PREFIX.length());
		}

		return null;
	}
}
