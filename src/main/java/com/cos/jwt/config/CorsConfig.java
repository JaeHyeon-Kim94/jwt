package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter(){
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); //서버가 응답할때 json을 자바스크립트에서 받아 처리할 수 있게 할지를 설정. false로 하면 json이 javascript쪽으로 오지 않음.
        config.addAllowedOrigin("*");   // 모든 ip에 응답을 허용
        config.addAllowedHeader("*");   // 모든 header에 응답 허용
        config.addAllowedMethod("*");   // 모든 post, get, put, delete, patch 요청을 허용하겠다.
        //해당 uri pattern으로 들어오는 모든 request는 해당 config를 따른다
        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);
    }
}
