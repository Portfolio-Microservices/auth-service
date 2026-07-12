package com.portfolio.auth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.portfolio.auth.dto.AdminGrantAccessRequest;
import com.portfolio.auth.dto.AdminGrantAccessResponse;
import com.portfolio.auth.exception.ResourceNotFoundException;
import com.portfolio.auth.service.AdminService;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/v1/admin")
@Validated
@Slf4j
public class AdminController {

	@Autowired
	private AdminService adminService;

	@PostMapping("/grant-access")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<AdminGrantAccessResponse> grantAdminAccess(
			@Valid @RequestBody AdminGrantAccessRequest request) {
		try {
			log.info("Processing admin grant access request for email: {}", request.getEmail());
			AdminGrantAccessResponse response = adminService.grantAdminAccess(request.getEmail(),
					request.getSecurityQuestionAnswer());
			if (response.isSuccess()) {
				return ResponseEntity.ok(response);
			} else {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
			}
		} catch (ResourceNotFoundException e) {
			log.error("User not found for email: {}", request.getEmail());
			return ResponseEntity.status(HttpStatus.NOT_FOUND)
					.body(new AdminGrantAccessResponse(false, "User not found: " + e.getMessage()));
		} catch (Exception e) {
			log.error("Error granting admin access: {}", e.getMessage());
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new AdminGrantAccessResponse(false, "Error processing request: " + e.getMessage()));
		}
	}

	@PostMapping("/security-question")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<String> getSecurityQuestion() {
		try {
			String question = adminService.getSecurityQuestion();
			return ResponseEntity.ok(question);
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error retrieving security question");
		}
	}
}
