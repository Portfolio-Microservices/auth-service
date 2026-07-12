package com.portfolio.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public class AdminGrantAccessRequest {

	@Email
	@NotBlank
	private String email;

	@NotBlank
	private String securityQuestionAnswer;

	public AdminGrantAccessRequest() {
	}

	public AdminGrantAccessRequest(String email, String securityQuestionAnswer) {
		this.email = email;
		this.securityQuestionAnswer = securityQuestionAnswer;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getSecurityQuestionAnswer() {
		return securityQuestionAnswer;
	}

	public void setSecurityQuestionAnswer(String securityQuestionAnswer) {
		this.securityQuestionAnswer = securityQuestionAnswer;
	}
}
