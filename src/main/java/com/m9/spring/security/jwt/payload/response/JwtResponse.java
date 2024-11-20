package com.m9.spring.security.jwt.payload.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@Builder
public class JwtResponse {
	private String token;
	private String type;
	private String refreshToken;
	private Long id;
	private String username;
	private String email;
	private final List<String> roles;
}
