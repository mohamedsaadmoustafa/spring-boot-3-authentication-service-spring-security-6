package com.m9.spring.security.jwt.advice;

import lombok.Getter;

@Getter
public enum ErrorCode {
    ROLE_NOT_FOUND(1001, "Role not found"),
    USERNAME_ALREADY_EXISTS(1002, "Username already exists"),
    EMAIL_ALREADY_EXISTS(1003, "Email already exists"),
    INVALID_ACCESS_TOKEN(1004, "Invalid token"),
    INVALID_REFRESH_TOKEN(1005, "Invalid token"),
    ACCESS_TOKEN_EXPIRED(1006, "Access token has expired"),
    REFRESH_ACCESS_TOKEN_EXPIRED(1007, "Refresh token has expired"),
    ACCESS_DENIED(1008, "Access is denied"),
    USER_NOT_FOUND(1009, "User not found");

    private final int code;
    private final String message;

    ErrorCode(int code, String message) {
        this.code = code;
        this.message = message;
    }

}
