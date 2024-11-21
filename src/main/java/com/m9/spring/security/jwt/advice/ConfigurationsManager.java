package com.m9.spring.security.jwt.advice;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import lombok.Getter;
import lombok.Setter;

@Configuration
@ConfigurationProperties(prefix = ConfigurationsManager.CONFIG_PREFIX)
@Validated
@Getter
@Setter
public class ConfigurationsManager {
    public static final String CONFIG_PREFIX = "token";

    @NotNull
    private Long accessExpireSeconds;

    @NotNull
    private Long refreshExpireSeconds;

    @NotBlank
    private String accessSigningKey;

    public long getAccessExpireMillis() {
        return accessExpireSeconds * 1000;
    }

    public long getRefreshExpireMillis() {
        return refreshExpireSeconds * 1000;
    }
}
