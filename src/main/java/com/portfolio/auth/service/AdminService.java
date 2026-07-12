package com.portfolio.auth.service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.portfolio.auth.dto.AdminGrantAccessResponse;
import com.portfolio.auth.entity.User;
import com.portfolio.auth.entity.User.UserRole;
import com.portfolio.auth.exception.ResourceNotFoundException;
import com.portfolio.auth.repository.UserRepository;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class AdminService {

	@Autowired
	private UserRepository userRepository;

	private static final String SECURITY_QUESTION_ANSWER = "IMPL";
	private static final int MAX_FAILED_ATTEMPTS = 3;
	private static final long FAILED_ATTEMPT_WINDOW_MINUTES = 30;
	private static final long LOCK_DURATION_MINUTES = 30;

	private final ConcurrentHashMap<String, FailedAttempt> failedAttempts = new ConcurrentHashMap<>();
	private final ConcurrentHashMap<String, LockoutInfo> lockoutMap = new ConcurrentHashMap<>();

	private static class FailedAttempt {
		int count;
		LocalDateTime firstAttemptTime;

		FailedAttempt() {
			this.count = 1;
			this.firstAttemptTime = LocalDateTime.now();
		}

		boolean isExpired() {
			return Duration.between(firstAttemptTime, LocalDateTime.now()).toMinutes() >= FAILED_ATTEMPT_WINDOW_MINUTES;
		}
	}

	private static class LockoutInfo {
		LocalDateTime lockedUntil;

		LockoutInfo() {
			this.lockedUntil = LocalDateTime.now().plusMinutes(LOCK_DURATION_MINUTES);
		}

		boolean isLocked() {
			return LocalDateTime.now().isBefore(lockedUntil);
		}

		long getRemainingMinutes() {
			if (!isLocked()) {
				return 0;
			}
			return Duration.between(LocalDateTime.now(), lockedUntil).toMinutes();
		}
	}

	@Transactional
	public AdminGrantAccessResponse grantAdminAccess(String email, String answer) {
		log.info("Processing admin access request for email: {}", email);

		if (isUserLockedOut(email)) {
			long remainingMinutes = getRemainingLockoutTime(email);
			String message = String.format("Account locked. Try again in %d minutes.", remainingMinutes);
			log.warn("User locked out: {}", email);
			return new AdminGrantAccessResponse(false, message);
		}

		if (!SECURITY_QUESTION_ANSWER.equals(answer)) {
			log.warn("Invalid security answer for email: {}", email);
			recordFailedAttempt(email);
			int remainingAttempts = MAX_FAILED_ATTEMPTS - getFailedAttemptCount(email);
			if (remainingAttempts <= 0) {
				lockoutUser(email);
				return new AdminGrantAccessResponse(false,
						"Maximum failed attempts reached. Account locked for 30 minutes.");
			}
			return new AdminGrantAccessResponse(false,
					String.format("Invalid answer. %d attempts remaining.", remainingAttempts));
		}

		clearFailedAttempts(email);

		User user = userRepository.findByEmail(email)
				.orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));

		if (UserRole.ADMIN.equals(user.getRole())) {
			return new AdminGrantAccessResponse(false, "User is already an admin");
		}

		user.setRole(UserRole.ADMIN);
		User updatedUser = userRepository.save(user);

		log.info("Admin access granted for {}", email);
		return new AdminGrantAccessResponse(true, "Admin access granted successfully", email,
				updatedUser.getRole().toString());
	}

	private void recordFailedAttempt(String email) {
		failedAttempts.compute(email, (key, existingAttempt) -> {
			if (existingAttempt == null) {
				return new FailedAttempt();
			}
			if (existingAttempt.isExpired()) {
				log.debug("Resetting expired attempts for {}", email);
				return new FailedAttempt();
			}
			existingAttempt.count++;
			return existingAttempt;
		});
		log.debug("Failed attempt count for {} = {}", email, getFailedAttemptCount(email));
	}

	private int getFailedAttemptCount(String email) {
		FailedAttempt attempt = failedAttempts.get(email);
		if (attempt == null) {
			return 0;
		}
		if (attempt.isExpired()) {
			failedAttempts.remove(email);
			return 0;
		}
		return attempt.count;
	}

	private void clearFailedAttempts(String email) {
		failedAttempts.remove(email);
		log.debug("Cleared failed attempts for {}", email);
	}

	private void lockoutUser(String email) {
		lockoutMap.put(email, new LockoutInfo());
		failedAttempts.remove(email);
		log.warn("User locked for 30 mins: {}", email);
	}

	private boolean isUserLockedOut(String email) {
		LockoutInfo lockout = lockoutMap.get(email);
		if (lockout == null) {
			return false;
		}
		if (lockout.isLocked()) {
			return true;
		}
		lockoutMap.remove(email);
		return false;
	}

	private long getRemainingLockoutTime(String email) {
		LockoutInfo lockout = lockoutMap.get(email);
		if (lockout == null) {
			return 0;
		}
		return lockout.getRemainingMinutes();
	}

	public String getSecurityQuestion() {
		return "What is the implementation answer?";
	}
}
