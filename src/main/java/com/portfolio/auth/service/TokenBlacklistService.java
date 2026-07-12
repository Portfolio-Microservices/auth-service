package com.portfolio.auth.service;

import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import com.portfolio.auth.security.JwtTokenProvider;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class TokenBlacklistService {

	@Autowired
	private JwtTokenProvider jwtTokenProvider;

	private final ConcurrentHashMap<String, Long> blacklistedTokens = new ConcurrentHashMap<>();

	public void blacklistToken(String token) {
		try {
			long expirationTime = jwtTokenProvider.getExpirationTimeFromToken(token);
			blacklistedTokens.put(token, expirationTime);
			log.info("Token blacklisted successfully. Total blacklisted tokens: {}", blacklistedTokens.size());
		} catch (Exception e) {
			log.error("Error blacklisting token: {}", e.getMessage());
		}
	}

	public boolean isTokenBlacklisted(String token) {
		if (!blacklistedTokens.containsKey(token)) {
			return false;
		}

		Long expirationTime = blacklistedTokens.get(token);
		long currentTime = System.currentTimeMillis();

		if (currentTime > expirationTime) {
			blacklistedTokens.remove(token);
			return false;
		}

		return true;
	}

	public void removeTokenFromBlacklist(String token) {
		blacklistedTokens.remove(token);
		log.debug("Token removed from blacklist");
	}

	@Scheduled(fixedRate = 300000)
	public void cleanupExpiredTokens() {
		long currentTime = System.currentTimeMillis();
		int initialSize = blacklistedTokens.size();

		blacklistedTokens.entrySet().removeIf(entry -> currentTime > entry.getValue());

		int removedCount = initialSize - blacklistedTokens.size();
		if (removedCount > 0) {
			log.debug("Cleaned up {} expired tokens from blacklist", removedCount);
		}
	}

	public int getBlacklistedTokenCount() {
		return blacklistedTokens.size();
	}

	public void clearAllBlacklistedTokens() {
		int count = blacklistedTokens.size();
		blacklistedTokens.clear();
		log.warn("Cleared {} blacklisted tokens", count);
	}
}
