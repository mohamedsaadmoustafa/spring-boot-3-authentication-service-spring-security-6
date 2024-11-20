package com.m9.spring.security.jwt.advice;


import com.m9.spring.security.jwt.exception.CustomException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ControllerAdvice {

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
}
