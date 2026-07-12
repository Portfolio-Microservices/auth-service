package com.portfolio.auth.security;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Collection;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenProvider {

	@Value("${jwt.secret}")
	private String jwtSecret;

	@Value("${jwt.expiration:900000}")
	private long jwtExpirationMs;

	@Value("${jwt.refreshExpiration:604800000}")
	private long jwtRefreshExpirationMs;

	private Key getSigningKey() {
		return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
	}

	public String generateToken(UserPrincipal userPrincipal) {
		String role = extractRole(userPrincipal.getAuthorities());
		return buildToken(userPrincipal.getUsername(), userPrincipal.getId(), role, jwtExpirationMs, "ACCESS");
	}

	public String generateRefreshToken(UserPrincipal userPrincipal) {
		String role = extractRole(userPrincipal.getAuthorities());
		return buildToken(userPrincipal.getUsername(), userPrincipal.getId(), role, jwtRefreshExpirationMs, "REFRESH");
	}

	private String buildToken(String username, Long userId, String role, long expiry, String type) {
		Date now = new Date();
		Date expiryDate = new Date(now.getTime() + expiry);

		if (role == null || role.isBlank()) {
			throw new RuntimeException("Role cannot be null when generating JWT");
		}

		if (!role.startsWith("ROLE_")) {
			role = "ROLE_" + role;
		}

		return Jwts.builder().setSubject(username).claim("userId", userId).claim("role", role).claim("type", type)
				.setIssuedAt(now).setExpiration(expiryDate).signWith(getSigningKey(), SignatureAlgorithm.HS512)
				.compact();
	}

	private String extractRole(Collection<?> authorities) {
		if (authorities == null || authorities.isEmpty()) {
			throw new RuntimeException("User has no authorities");
		}
		return authorities.iterator().next().toString();
	}

	public String getUsernameFromToken(String token) {
		return getAllClaims(token).getSubject();
	}

	public Long getUserIdFromToken(String token) {
		return getAllClaims(token).get("userId", Long.class);
	}

	public String getRoleFromToken(String token) {
		return getAllClaims(token).get("role", String.class);
	}

	public String getTokenType(String token) {
		return getAllClaims(token).get("type", String.class);
	}

	public boolean validateToken(String token) {
		try {
			Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token);
			return true;
		} catch (Exception ex) {
			System.err.println("JWT validation failed: " + ex.getMessage());
			return false;
		}
	}

	private Claims getAllClaims(String token) {
		return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody();
	}

	public long getJwtExpirationMs() {
		return jwtExpirationMs;
	}

	public long getExpirationTimeFromToken(String token) {
		Date expirationDate = getAllClaims(token).getExpiration();
		return expirationDate.getTime();
	}
}
