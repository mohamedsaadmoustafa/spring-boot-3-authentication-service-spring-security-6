package com.m9.spring.security.jwt.payload.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
@Builder
public class JwtTokens {
  private String accessToken;
  private String refreshToken;
}
