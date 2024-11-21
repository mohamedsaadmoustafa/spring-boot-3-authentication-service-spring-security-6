package com.m9.spring.security.jwt.security.jwt;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import com.m9.spring.security.jwt.advice.ConfigurationsManager;
import com.m9.spring.security.jwt.security.services.UserDetailsImpl;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;

@Service
@Slf4j
@RequiredArgsConstructor
public class JwtUtils {
  private final ConfigurationsManager configurationsManager;

  private SecretKey getSigningKey() {
    String jwtSecret = configurationsManager.getAccessSigningKey();
    byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  public String generateJwtToken(UserDetailsImpl userPrincipal) {
    return this.generateTokenFromUsername(userPrincipal.getUsername());
  }

  public String generateTokenFromUsername(String username) {
    Date iat = new Date();
    Long accessTokenExpireSeconds = configurationsManager.getAccessExpireSeconds();
    Duration expirationDuration = Duration.ofSeconds(accessTokenExpireSeconds);
    Instant expirationInstant = iat.toInstant().plus(expirationDuration);
    Date expirationDate = Date.from(expirationInstant);
    return Jwts.builder()
            .subject(username)
            .issuedAt(iat)
            .expiration(expirationDate)
            .signWith(getSigningKey())
            .compact();
  }

  public String getUserNameFromJwtToken(String token) {
    try {
      return this.getClaims(token).getSubject();
    } catch (Exception e) {
      log.error("Failed to parse JWT token: {}", e.getMessage());
    }
    return null;
  }

  public Claims getClaims(String token) {
      SecretKey key = getSigningKey();
      JwtParser parser = Jwts.parser().verifyWith(key).build();
      return parser.parseSignedClaims(token).getPayload();
  }

  public boolean validateJwtToken(String authToken) {
    try {
      SecretKey key = getSigningKey();
      JwtParser parser = Jwts.parser().verifyWith(key).build();
      parser.parseSignedClaims(authToken);
      return true;
    } catch (Exception e) {
      log.error("Invalid JWT token: {}", e.getMessage());
    }
    return false;
  }
}
