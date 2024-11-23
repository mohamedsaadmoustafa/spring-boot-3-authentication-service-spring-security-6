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
import com.m9.spring.security.jwt.security.services.UserDetailsImpl;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
@Slf4j
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;

    public JwtResponse authenticateUser(LoginRequest loginRequest) {
        log.info("Authenticating user with username: {}", loginRequest.getUsername());
        @NotBlank String userName = loginRequest.getUsername();
        @NotBlank String password = loginRequest.getPassword();
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userName, password);
        Authentication authentication = authenticationManager.authenticate(auth);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        log.debug("User '{}' authenticated successfully", userName);
        String jwt = jwtUtils.generateJwtToken(userDetails);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());
        log.debug("Generated refresh token for user '{}'", userName);
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        return new JwtResponse(
                jwt, "Bearer", refreshToken.getToken(), userDetails.getId(),
                userName, userDetails.getEmail(), roles
        );
    }

    public void registerUser(SignupRequest signUpRequest) {
        log.info("Registering user with username: {}, email: {}", signUpRequest.getUsername(), signUpRequest.getEmail());
        validateSignupRequest(signUpRequest);
        User user = new User(
                signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword())
        );
        Set<Role> roles = resolveRoles(signUpRequest.getRole());
        user.setRoles(roles);
        userRepository.save(user);
        log.info("User {} registered successfully", user.getUsername());
    }

    private void validateSignupRequest(SignupRequest signUpRequest) {
        log.debug("Validating signup request for username: {} and email: {}", signUpRequest.getUsername(), signUpRequest.getEmail());
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            log.error("Username {} already exists", signUpRequest.getUsername());
            throw new CustomException(ErrorCode.USERNAME_ALREADY_EXISTS);
        }
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            log.error("Email {} already exists", signUpRequest.getEmail());
            throw new CustomException(ErrorCode.EMAIL_ALREADY_EXISTS);
        }
    }

    private Set<Role> resolveRoles(Set<String> roleNames) {
        log.debug("Resolving roles: {}", roleNames);
        if (roleNames == null || roleNames.isEmpty()) {
            log.debug("No roles provided, defaulting to ROLE_USER");
            return Set.of(findRoleByName(ERole.ROLE_USER));
        }
        return roleNames.stream()
                .map(this::mapRoleNameToRole)
                .collect(Collectors.toSet());
    }

    private Role mapRoleNameToRole(String roleName) {
        log.debug("Mapping role name: {}", roleName);
        ERole eRole = switch (roleName.toLowerCase()) {
            case "admin" -> ERole.ROLE_ADMIN;
            case "mod" -> ERole.ROLE_MODERATOR;
            default -> ERole.ROLE_USER;
        };
        return findRoleByName(eRole);
    }

    private Role findRoleByName(ERole roleName) {
        log.debug("Finding role by name: {}", roleName);
        return roleRepository.findByName(roleName)
                .orElseThrow(() -> {
                    log.error("Role {} not found", roleName);
                    return new CustomException(ErrorCode.ROLE_NOT_FOUND);
                });
    }

    public JwtTokens refreshToken(String requestRefreshToken) {
        log.info("Refreshing token");
        return refreshTokenService.findByRefreshToken(requestRefreshToken);
    }

    public void logoutUser() {
        UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        log.info("Logging out user: {}", userDetails.getUsername());
        refreshTokenService.deleteByUserId(userDetails.getId());
        log.debug("User {} logged out successfully", userDetails.getUsername());
    }
}
