package com.portfolio.auth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.portfolio.auth.dto.AuthRequest;
import com.portfolio.auth.dto.AuthResponse;
import com.portfolio.auth.dto.LogoutResponse;
import com.portfolio.auth.dto.RefreshTokenRequest;
import com.portfolio.auth.dto.SignupRequest;
import com.portfolio.auth.dto.UserDto;
import com.portfolio.auth.entity.User;
import com.portfolio.auth.entity.User.UserRole;
import com.portfolio.auth.repository.UserRepository;
import com.portfolio.auth.security.JwtTokenProvider;
import com.portfolio.auth.security.UserPrincipal;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class AuthService {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtTokenProvider jwtTokenProvider;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private TokenBlacklistService tokenBlacklistService;

	@Transactional
	public AuthResponse login(AuthRequest authRequest) throws AuthenticationException {
		log.info("Attempting login for user: {}", authRequest.getEmail());

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(authRequest.getEmail(), authRequest.getPassword()));

		UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

		String accessToken = jwtTokenProvider.generateToken(userPrincipal);
		String refreshToken = jwtTokenProvider.generateRefreshToken(userPrincipal);

		log.info("Login successful for user: {}", authRequest.getEmail());

		return new AuthResponse(accessToken, refreshToken, "Bearer", jwtTokenProvider.getJwtExpirationMs(),
				getUserDtoFromPrincipal(userPrincipal));
	}

	@Transactional
	public AuthResponse signup(SignupRequest signupRequest) {
		log.info("Attempting to register new user: {}", signupRequest.getEmail());

		if (userRepository.existsByUsername(signupRequest.getUsername())) {
			log.warn("Registration failed: Username already taken: {}", signupRequest.getUsername());
			throw new IllegalArgumentException("Username is already taken");
		}

		if (userRepository.existsByEmail(signupRequest.getEmail())) {
			log.warn("Registration failed: Email already registered: {}", signupRequest.getEmail());
			throw new IllegalArgumentException("Email is already registered");
		}

		User user = new User();
		user.setUsername(signupRequest.getUsername());
		user.setEmail(signupRequest.getEmail());
		user.setPassword(passwordEncoder.encode(signupRequest.getPassword()));
		user.setRole(UserRole.USER);
		user.setEnabled(true);

		User savedUser = userRepository.save(user);
		log.info("User registered successfully with ID: {}", savedUser.getId());

		UserPrincipal userPrincipal = UserPrincipal.create(savedUser);
		String accessToken = jwtTokenProvider.generateToken(userPrincipal);
		String refreshToken = jwtTokenProvider.generateRefreshToken(userPrincipal);

		return new AuthResponse(accessToken, refreshToken, "Bearer", jwtTokenProvider.getJwtExpirationMs(),
				getUserDtoFromPrincipal(userPrincipal));
	}

	@Transactional
	public AuthResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
		if (!jwtTokenProvider.validateToken(refreshTokenRequest.getRefreshToken())) {
			throw new IllegalArgumentException("Invalid or expired refresh token");
		}

		Long userId = jwtTokenProvider.getUserIdFromToken(refreshTokenRequest.getRefreshToken());

		User user = userRepository.findById(userId).orElseThrow(() -> new IllegalArgumentException("User not found"));

		UserPrincipal userPrincipal = UserPrincipal.create(user);
		String accessToken = jwtTokenProvider.generateToken(userPrincipal);

		return new AuthResponse(accessToken, refreshTokenRequest.getRefreshToken(), "Bearer",
				jwtTokenProvider.getJwtExpirationMs(), getUserDtoFromPrincipal(userPrincipal));
	}

	private UserDto getUserDtoFromPrincipal(UserPrincipal userPrincipal) {
		String role = userPrincipal.getAuthorities().iterator().next().getAuthority().replace("ROLE_", "");
		return new UserDto(userPrincipal.getId(), userPrincipal.getUsername(), userPrincipal.getEmail(), role);
	}

	@Transactional
	public LogoutResponse logout(String accessToken) {
		log.info("Processing logout request");

		try {
			if (!jwtTokenProvider.validateToken(accessToken)) {
				log.warn("Attempted logout with invalid token");
				return new LogoutResponse(false, "Invalid or expired token");
			}

			String username = jwtTokenProvider.getUsernameFromToken(accessToken);
			tokenBlacklistService.blacklistToken(accessToken);

			log.info("User logged out successfully: {}", username);
			return new LogoutResponse(true, "Logged out successfully");
		} catch (Exception e) {
			log.error("Error during logout: {}", e.getMessage());
			return new LogoutResponse(false, "Error during logout: " + e.getMessage());
		}
	}
}
