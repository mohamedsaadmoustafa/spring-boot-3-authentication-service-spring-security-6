package com.m9.spring.security.jwt.payload.request;

import lombok.Getter;
import lombok.Setter;

import jakarta.validation.constraints.NotBlank;

@Setter
@Getter
public class LoginRequest {
	@NotBlank
	private String username;

	@NotBlank
	private String password;

}
