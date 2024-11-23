package com.m9.spring.security.jwt.services;

import com.m9.spring.security.jwt.advice.ConfigurationsManager;
import com.m9.spring.security.jwt.advice.ErrorCode;
import com.m9.spring.security.jwt.entities.RefreshToken;
import com.m9.spring.security.jwt.entities.User;
import com.m9.spring.security.jwt.exception.CustomException;
import com.m9.spring.security.jwt.payload.response.JwtTokens;
import com.m9.spring.security.jwt.repository.RefreshTokenRepository;
import com.m9.spring.security.jwt.repository.UserRepository;
import com.m9.spring.security.jwt.security.jwt.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {
  private final RefreshTokenRepository refreshTokenRepository;
  private final UserRepository userRepository;
  private final JwtUtils jwtUtils;
  private final ConfigurationsManager configurationsManager;

  public JwtTokens findByRefreshToken(String requestRefreshToken) {
    log.info("Processing refresh token: {}", requestRefreshToken);
    return refreshTokenRepository.findByToken(requestRefreshToken)
            .map(this::validateTokenExpiration)
            .map(RefreshToken::getUser)
            .map(user -> {
              log.info("Valid refresh token for user: {}", user.getUsername());
              String accessToken = jwtUtils.generateTokenFromUsername(user.getUsername());
              return new JwtTokens(accessToken, requestRefreshToken);
            })
            .orElseThrow(() -> {
              log.error("Invalid refresh token: {}", requestRefreshToken);
              return new CustomException(ErrorCode.INVALID_REFRESH_TOKEN);
            });
  }

  public RefreshToken createRefreshToken(Long userId) {
    log.info("Creating refresh token for user ID: {}", userId);
    User user = this.getUserById(userId);
    RefreshToken refreshToken = new RefreshToken();
    refreshToken.setUser(user);
    Long refreshTokenDurationMs = configurationsManager.getRefreshExpireSeconds();
    refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
    refreshToken.setToken(UUID.randomUUID().toString());
    refreshToken = refreshTokenRepository.save(refreshToken);
    log.info("Refresh token created successfully for user: {}", user.getUsername());
    return refreshToken;
  }

  public RefreshToken validateTokenExpiration(RefreshToken token) {
    log.debug("Validating expiration for token: {}", token.getToken());
    if (token.getExpiryDate().isBefore(Instant.now())) {
      log.warn("Token expired: {}", token.getToken());
      refreshTokenRepository.delete(token);
      throw new CustomException(ErrorCode.REFRESH_ACCESS_TOKEN_EXPIRED);
    }
    log.debug("Token is valid: {}", token.getToken());
    return token;
  }

  @Transactional
  public void deleteByUserId(Long userId) {
    log.info("Deleting refresh tokens for user ID: {}", userId);
    User user = this.getUserById(userId);
    refreshTokenRepository.deleteByUser(user);
    log.info("All refresh tokens deleted for user: {}", user.getUsername());
  }

  private User getUserById(Long userId) {
    return userRepository.findById(userId)
            .orElseThrow(() -> {
              log.error("User not found for ID: {}", userId);
              return new CustomException(ErrorCode.USER_NOT_FOUND);
            });
  }
}
