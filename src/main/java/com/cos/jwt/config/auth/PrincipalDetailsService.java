package com.cos.jwt.config.auth;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://localhost:8080/login request가 왔을 때 동작. but SecurityConfig에서 fomLogin().disable()으로 인해
// 원래는 기본적으로 시큐리티에서 동작하는 login path가 동작하지 않음.
// 따라서 PrincipalDetailsService를 직접 건드려주는 필터 필요함.
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = repository.findByUsername(username);
        return new PrincipalDetails(userEntity);
    }
}
