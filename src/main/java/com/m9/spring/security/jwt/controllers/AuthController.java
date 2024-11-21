package com.m9.spring.security.jwt.controllers;

import com.m9.spring.security.jwt.advice.ApiResponse;
import com.m9.spring.security.jwt.payload.request.LoginRequest;
import com.m9.spring.security.jwt.payload.request.SignupRequest;
import com.m9.spring.security.jwt.payload.request.TokenRefreshRequest;
import com.m9.spring.security.jwt.payload.response.JwtResponse;
import com.m9.spring.security.jwt.payload.response.JwtTokens;
import com.m9.spring.security.jwt.services.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
  private final AuthService authService;

  @PostMapping("/login")
  public ResponseEntity<ApiResponse<JwtResponse>> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
    JwtResponse jwtResponse = authService.authenticateUser(loginRequest);
    return ResponseEntity.ok(ApiResponse.success("Login successful!", jwtResponse));
  }

  @PostMapping("/signup")
  public ResponseEntity<ApiResponse<Void>> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    authService.registerUser(signUpRequest);
    return ResponseEntity.ok(ApiResponse.success("User registered successfully!", null));
  }

  @PostMapping("/refresh-token")
  public ResponseEntity<ApiResponse<JwtTokens>> refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
    JwtTokens tokens = authService.refreshToken(request.getRefreshToken());
    return ResponseEntity.ok(ApiResponse.success("Token refreshed successfully!", tokens));
  }

  @PostMapping("/logout")
  public ResponseEntity<ApiResponse<Void>> logoutUser() {
    authService.logoutUser();
    return ResponseEntity.ok(ApiResponse.success("Log out successful!", null));
  }
}
