package com.m9.spring.security.jwt.security.services;

import com.m9.spring.security.jwt.advice.ErrorCode;
import com.m9.spring.security.jwt.entities.User;
import com.m9.spring.security.jwt.exception.CustomException;
import com.m9.spring.security.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
        return UserDetailsImpl.build(user);
    }

//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        User user = userRepository.findByUsername(username)
//                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
//        Set<GrantedAuthority> authorities = user
//                .getRoles()
//                .stream()
//                .map((role) -> new SimpleGrantedAuthority(
//                        role.getName().toString())
//                )
//                .collect(Collectors.toSet());
//        return new org.springframework.security.core.userdetails.User(
//                username,
//                user.getPassword(),
//                authorities
//        );
//    }
}