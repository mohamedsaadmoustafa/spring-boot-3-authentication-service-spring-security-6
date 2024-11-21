package com.m9.spring.security.jwt.services;

import java.time.Instant;
import java.util.UUID;

import com.m9.spring.security.jwt.advice.ConfigurationsManager;
import com.m9.spring.security.jwt.advice.ErrorCode;
import com.m9.spring.security.jwt.entities.User;
import com.m9.spring.security.jwt.exception.CustomException;
import com.m9.spring.security.jwt.payload.response.JwtTokens;
import com.m9.spring.security.jwt.security.jwt.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.m9.spring.security.jwt.entities.RefreshToken;
import com.m9.spring.security.jwt.repository.RefreshTokenRepository;
import com.m9.spring.security.jwt.repository.UserRepository;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {
  private final RefreshTokenRepository refreshTokenRepository;
  private final UserRepository userRepository;
  private final JwtUtils jwtUtils;
  private final ConfigurationsManager configurationsManager;

  public JwtTokens findByRefreshToken(String requestRefreshToken) {
    return refreshTokenRepository.findByToken(requestRefreshToken)
            .map(this::verifyExpiration)
            .map(RefreshToken::getUser)
            .map(user -> {
              String token = jwtUtils.generateTokenFromUsername(user.getUsername());
              return new JwtTokens(token, requestRefreshToken);
            })
            .orElseThrow(() -> new CustomException(ErrorCode.INVALID_REFRESH_TOKEN));
  }

  public RefreshToken createRefreshToken(Long userId) {
    RefreshToken refreshToken = new RefreshToken();
    User user = userRepository.findById(userId)
            .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
    refreshToken.setUser(user);
    Long refreshTokenDurationMs = configurationsManager.getRefreshExpireSeconds();
    refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
    refreshToken.setToken(UUID.randomUUID().toString());
    refreshToken = refreshTokenRepository.save(refreshToken);
    return refreshToken;
  }

  public RefreshToken verifyExpiration(RefreshToken token) {
    if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
      refreshTokenRepository.delete(token);
      throw new CustomException(ErrorCode.REFRESH_ACCESS_TOKEN_EXPIRED);
    }
    return token;
  }

  @Transactional
  public void deleteByUserId(Long userId) {
    User user = userRepository.findById(userId)
            .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
    refreshTokenRepository.deleteByUser(user);
  }
}
