package com.portfolio.auth.security;

import java.io.IOException;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {

		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType("application/json");

		final ObjectMapper mapper = new ObjectMapper();

		response.getWriter()
				.write(mapper.writeValueAsString(
						ApiError.builder().status(HttpServletResponse.SC_UNAUTHORIZED).error("Unauthorized")
								.message("Authentication is required. Please provide a valid JWT token.").build()));
	}
}

class ApiError {
	private int status;
	private String error;
	private String message;

	public ApiError(int status, String error, String message) {
		this.status = status;
		this.error = error;
		this.message = message;
	}

	public static ApiErrorBuilder builder() {
		return new ApiErrorBuilder();
	}

	public int getStatus() {
		return status;
	}

	public String getError() {
		return error;
	}

	public String getMessage() {
		return message;
	}

	static class ApiErrorBuilder {
		private int status;
		private String error;
		private String message;

		ApiErrorBuilder status(int status) {
			this.status = status;
			return this;
		}

		ApiErrorBuilder error(String error) {
			this.error = error;
			return this;
		}

		ApiErrorBuilder message(String message) {
			this.message = message;
			return this;
		}

		ApiError build() {
			return new ApiError(status, error, message);
		}
	}
}
