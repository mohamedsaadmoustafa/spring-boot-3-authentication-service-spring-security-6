package com.m9.spring.security.jwt.entities;

import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

import javax.persistence.*;

@Setter
@Getter
@Entity(name = "refresh_token")
public class RefreshToken {
  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  private long id;

  @OneToOne
  @JoinColumn(name = "user_id", referencedColumnName = "id")
  private User user;

  @Column(nullable = false, unique = true)
  private String token;

  @Column(nullable = false)
  private Instant expiryDate;

  public RefreshToken() {
  }
}
