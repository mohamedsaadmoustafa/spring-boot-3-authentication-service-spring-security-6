package com.m9.spring.security.jwt.security.services;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.m9.spring.security.jwt.advice.ErrorCode;
import com.m9.spring.security.jwt.entities.User;
import com.m9.spring.security.jwt.exception.CustomException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.m9.spring.security.jwt.entities.RefreshToken;
import com.m9.spring.security.jwt.repository.RefreshTokenRepository;
import com.m9.spring.security.jwt.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
  @Value("${m9.app.jwtRefreshExpirationMs}")
  private Long refreshTokenDurationMs;

  private final RefreshTokenRepository refreshTokenRepository;
  private final UserRepository userRepository;

  public Optional<RefreshToken> findByToken(String token) {
    return refreshTokenRepository.findByToken(token);
  }

  public RefreshToken createRefreshToken(Long userId) {
    RefreshToken refreshToken = new RefreshToken();
    User user = userRepository.findById(userId)
            .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND.getCode(), ErrorCode.USER_NOT_FOUND.getMessage()));
    refreshToken.setUser(user);
    refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
    refreshToken.setToken(UUID.randomUUID().toString());
    refreshToken = refreshTokenRepository.save(refreshToken);
    return refreshToken;
  }

  public RefreshToken verifyExpiration(RefreshToken token) {
    if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
      refreshTokenRepository.delete(token);
      throw new CustomException(ErrorCode.REFRESH_ACCESS_TOKEN_EXPIRED.getCode(), ErrorCode.REFRESH_ACCESS_TOKEN_EXPIRED.getMessage());
    }
    return token;
  }

  @Transactional
  public void deleteByUserId(Long userId) {
    User user = userRepository.findById(userId)
            .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND.getCode(), ErrorCode.USER_NOT_FOUND.getMessage()));
    refreshTokenRepository.deleteByUser(user);
  }
}
