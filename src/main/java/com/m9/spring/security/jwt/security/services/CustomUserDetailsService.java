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

    /**
     * Load user by username and return UserDetails object.
     *
     * @param username the username of the user to load
     * @return UserDetails implementation for Spring Security
     * @throws UsernameNotFoundException if the user is not found
     */
    @Transactional
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
        return UserDetailsImpl.build(user);
    }
}
