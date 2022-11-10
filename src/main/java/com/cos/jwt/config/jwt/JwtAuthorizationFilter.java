package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.cos.jwt.config.jwt.JwtProperties.*;

//Spring security Filterchain중 BasicAuthenticationFilter라는 것이 있음.
//문서에 따르면 BASIC authorization 헤더를 가진 요청을 처리하고 결과를 SecurityContextHolder에 put한다.
//Basic Authorization의 schema는 Base64 인코딩된 username:password 토큰.
//ex) Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository repository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository repository) {
        super(authenticationManager);
        this.repository = repository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader : " + jwtHeader);
        //1. header Authorization에 jwt가 있는지 확인
        if(jwtHeader == null || !jwtHeader.startsWith("Bearer")){
            System.out.println("jwt null이므로 다음 필터로 이동");
            chain.doFilter(request, response);
            return;
        }

        //넘어온 JWT를 검증해서 정상적인 사용자인지 확인
        String jwtToken = request.getHeader(HEADER_STRING).replace(TOKEN_PREFIX, "");

        String username = JWT.require(Algorithm.HMAC512(SECRET))
                .build()
                //만약 jwt가 유효하지 않아 signature resulted invalid시에는
                //SignatureVerificationException 발생하는데 이부분은 예외처리 해주자.
                .verify(jwtToken)
                .getClaim("username").asString();

        if(username != null){
            System.out.println("username 정상.");
            User userEntity = repository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            //Jwt 서명을 통해 서명이 정상이면 Authentication 객체를 만들어준다.
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            //강제로 시큐리티 세션에 접근해 Authentication 객체 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        }

        System.out.println("jwtHeader : " + jwtHeader);
    }
}
