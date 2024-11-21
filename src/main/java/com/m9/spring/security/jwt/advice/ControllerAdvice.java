package com.m9.spring.security.jwt.advice;

import com.m9.spring.security.jwt.exception.CustomException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

import jakarta.validation.ConstraintViolationException;

@RestControllerAdvice
public class ControllerAdvice {

  // Custom application exception
  @ExceptionHandler(CustomException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseEntity<ApiResponse<Void>> handleCustomException(CustomException ex) {
    ApiResponse<Void> response = new ApiResponse<>(
            false,
            ex.getMessage(),
            ex.getErrorCode()
    );
    return ResponseEntity.badRequest().body(response);
  }

  // Validation errors for @Valid or @Validated
  @ExceptionHandler(MethodArgumentNotValidException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseEntity<ApiResponse<Void>> handleValidationException(MethodArgumentNotValidException ex) {
    String errorMessage = ex.getBindingResult().getFieldErrors().stream()
            .map(error -> error.getField() + ": " + error.getDefaultMessage())
            .findFirst()
            .orElse("Validation error");
    ApiResponse<Void> response = new ApiResponse<>(
            false,
            errorMessage,
            ex.getStatusCode().value()
    );
    return ResponseEntity.badRequest().body(response);
  }

  // Constraint violations (e.g., @Size, @Min, etc.)
  @ExceptionHandler(ConstraintViolationException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseEntity<ApiResponse<Void>> handleConstraintViolationException(ConstraintViolationException ex) {
    String errorMessage = ex.getConstraintViolations().stream()
            .map(violation -> violation.getPropertyPath() + ": " + violation.getMessage())
            .findFirst()
            .orElse("Constraint violation");
    ApiResponse<Void> response = new ApiResponse<>(
            false,
            errorMessage,
            HttpStatus.BAD_REQUEST.value()
    );
    return ResponseEntity.badRequest().body(response);
  }

  // Missing request parameters
  @ExceptionHandler(MissingServletRequestParameterException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseEntity<ApiResponse<Void>> handleMissingServletRequestParameterException(MissingServletRequestParameterException ex) {
    ApiResponse<Void> response = new ApiResponse<>(
            false,
            "Missing parameter: " + ex.getParameterName(),
            ex.getStatusCode().value()
    );
    return ResponseEntity.badRequest().body(response);
  }

  // Unsupported HTTP request methods
  @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
  @ResponseStatus(HttpStatus.METHOD_NOT_ALLOWED)
  public ResponseEntity<ApiResponse<Void>> handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException ex) {
    ApiResponse<Void> response = new ApiResponse<>(
            false,
            "Method not allowed: " + ex.getMethod(),
            ex.getStatusCode().value()
    );
    return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).body(response);
  }

  // Unsupported media types
  @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
  @ResponseStatus(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
  public ResponseEntity<ApiResponse<Void>> handleHttpMediaTypeNotSupportedException(HttpMediaTypeNotSupportedException ex) {
    ApiResponse<Void> response = new ApiResponse<>(
            false,
            "Unsupported media type: " + ex.getContentType(),
            ex.getStatusCode().value()
    );
    return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body(response);
  }

  // Security-related exceptions
  @ExceptionHandler(AccessDeniedException.class)
  @ResponseStatus(HttpStatus.FORBIDDEN)
  public ResponseEntity<ApiResponse<Void>> handleAccessDeniedException(AccessDeniedException ex) {
    ApiResponse<Void> response = new ApiResponse<>(
            false,
            "Access denied: " + ex.getMessage(),
            HttpStatus.FORBIDDEN.value()
    );
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
  }

  @ExceptionHandler(AuthenticationCredentialsNotFoundException.class)
  @ResponseStatus(HttpStatus.UNAUTHORIZED)
  public ResponseEntity<ApiResponse<Void>> handleAuthenticationCredentialsNotFoundException(AuthenticationCredentialsNotFoundException ex) {
    ApiResponse<Void> response = new ApiResponse<>(
            false,
            "Authentication required: " + ex.getMessage(),
            HttpStatus.UNAUTHORIZED.value()
    );
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
  }

  // Username not found in authentication
  @ExceptionHandler(UsernameNotFoundException.class)
  @ResponseStatus(HttpStatus.NOT_FOUND)
  public ResponseEntity<ApiResponse<Void>> handleUsernameNotFoundException(UsernameNotFoundException ex) {
    ApiResponse<Void> response = new ApiResponse<>(
            false,
            "User not found: " + ex.getMessage(),
            HttpStatus.NOT_FOUND.value()
    );
    return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
  }

  // Spring's ResponseStatusException (used in controllers)
  @ExceptionHandler(ResponseStatusException.class)
  public ResponseEntity<ApiResponse<Void>> handleResponseStatusException(ResponseStatusException ex) {
    ApiResponse<Void> response = new ApiResponse<>(
            false,
            ex.getMessage(),
            ex.getStatusCode().value()
    );
    return ResponseEntity.status(ex.getStatusCode()).body(response);
  }

  // Generic catch-all for unexpected exceptions
  @ExceptionHandler(Exception.class)
  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  public ResponseEntity<ApiResponse<Void>> handleGenericException(Exception ex) {
    ApiResponse<Void> response = new ApiResponse<>(
            false,
            ex.getMessage(),
            500
    );
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
  }
}
