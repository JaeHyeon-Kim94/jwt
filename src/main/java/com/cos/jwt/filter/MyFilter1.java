package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter1 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest)request;
        HttpServletResponse res = (HttpServletResponse) response;

//        if(req.getMethod().equals("POST")){
//            String headerAuth = req.getHeader("Authorization");
//            System.out.println("POST 요청됨");
//            System.out.println(headerAuth);
//
//            if(headerAuth.equals("cos")){
//                filterChain.doFilter(req, res);
//            }else{
//                PrintWriter out = res.getWriter();
//                out.print("인증 안됨");
//            }
//        }

        System.out.println("필터 1");

        filterChain.doFilter(req, res);
    }
}
