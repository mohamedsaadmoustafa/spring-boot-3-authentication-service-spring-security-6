package com.m9.spring.security.jwt.services;

import com.m9.spring.security.jwt.advice.ErrorCode;
import com.m9.spring.security.jwt.entities.RefreshToken;
import com.m9.spring.security.jwt.entities.Role;
import com.m9.spring.security.jwt.entities.User;
import com.m9.spring.security.jwt.enums.ERole;
import com.m9.spring.security.jwt.exception.CustomException;
import com.m9.spring.security.jwt.payload.request.LoginRequest;
import com.m9.spring.security.jwt.payload.request.SignupRequest;
import com.m9.spring.security.jwt.payload.response.JwtResponse;
import com.m9.spring.security.jwt.payload.response.JwtTokens;
import com.m9.spring.security.jwt.repository.RoleRepository;
import com.m9.spring.security.jwt.repository.UserRepository;
import com.m9.spring.security.jwt.security.jwt.JwtUtils;
import com.m9.spring.security.jwt.security.services.RefreshTokenService;
import com.m9.spring.security.jwt.security.services.UserDetailsImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;

    public JwtResponse authenticateUser(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        String jwt = jwtUtils.generateJwtToken(userDetails);
        List<String> roles = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());
        return new JwtResponse(jwt, "Bearer", refreshToken.getToken(),
                userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles);
    }

    public void registerUser(SignupRequest signUpRequest) {
        validateSignupRequest(signUpRequest);
        User user = new User(
                signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword())
        );
        Set<Role> roles = resolveRoles(signUpRequest.getRole());
        user.setRoles(roles);
        userRepository.save(user);
    }

    private void validateSignupRequest(SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            throw new CustomException(
                    ErrorCode.USERNAME_ALREADY_EXISTS.getCode(),
                    ErrorCode.USERNAME_ALREADY_EXISTS.getMessage()
            );
        }
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new CustomException(
                    ErrorCode.EMAIL_ALREADY_EXISTS.getCode(),
                    ErrorCode.EMAIL_ALREADY_EXISTS.getMessage()
            );
        }
    }

    private Set<Role> resolveRoles(Set<String> roleNames) {
        if (roleNames == null || roleNames.isEmpty()) {
            return Set.of(findRoleByName(ERole.ROLE_USER));
        }
        return roleNames.stream()
                .map(this::mapRoleNameToRole)
                .collect(Collectors.toSet());
    }

    private Role mapRoleNameToRole(String roleName) {
        ERole eRole = switch (roleName.toLowerCase()) {
            case "admin" -> ERole.ROLE_ADMIN;
            case "mod" -> ERole.ROLE_MODERATOR;
            default -> ERole.ROLE_USER;
        };
        return findRoleByName(eRole);
    }

    private Role findRoleByName(ERole roleName) {
        return roleRepository.findByName(roleName)
                .orElseThrow(() -> new CustomException(
                        ErrorCode.ROLE_NOT_FOUND.getCode(),
                        ErrorCode.ROLE_NOT_FOUND.getMessage()
                ));
    }

    public JwtTokens refreshToken(String requestRefreshToken) {
        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = jwtUtils.generateTokenFromUsername(user.getUsername());
                    return new JwtTokens(token, requestRefreshToken);
                })
                .orElseThrow(() -> new CustomException(ErrorCode.INVALID_REFRESH_TOKEN.getCode(), ErrorCode.INVALID_REFRESH_TOKEN.getMessage()));
    }

    public void logoutUser() {
        UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        refreshTokenService.deleteByUserId(userDetails.getId());
    }
}
