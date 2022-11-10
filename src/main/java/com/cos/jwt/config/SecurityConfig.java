package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Import({CorsConfig.class})
public class SecurityConfig {

    private final UserRepository repository;
    private final CorsFilter corsFilter;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.
                csrf().disable()
                //그냥 addFilter를 하면 filterChain에 등록되지 않은, 내가 만든 필터이기 때문에 스프링은 순서 정해달라고 함.
                //addFilterBefore 혹은 addFilterAfter
                //security filterchain 말고 그냥 filter를 내가 등록할 수도 있는데,(FilterConfig의 FilterRegistrationBean 참고)
                //security filterchain이 그냥 filter보다 먼저 실행됨.
                //.addFilterAfter(new MyFilter3(), FilterSecurityInterceptor.class)
                 //세션을 사용하지 않는 Stateless한 서버로 하겠다.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                //해당 위치에 기술함으로써 모든 요청은 해당 필터를 거침.
                // 또한 corsFilter 등록함으로써 내 서버는 cors 정책의 적용을 받지 않게 된다.
                //Controller에 @CrossOrigin 애너테이션을 걸어도 되지만, 인증이 필요한 요청은 모두 거부됨. 인증이 필요하지 않은 경우에만.
                //인증이 필요한 요청까지 받으려면 시큐리티 필터 등록 필요
                //폼 로그인 사용 X.
                .formLogin().disable()
                //일반적인 http 로그인 방식 사용X
                //http에서 쿠키는 동일 도메인에서만 요청이 올때 발동.(동일 출처 정책)
                //다른 도메인에서 쿠키를 javascript로 강제로 담아 보내는 경우에도 쿠키의 http only 설정값을 통해 거부됨.

                //그래서 header에 Authorization 이라는 키값에 ID, Password를 담아 보내는 방식이 http basic 방식인데,
                //확장성 문제는 해당되지 않지만 데이터 노출의 위험성이 존재함. 다만 http가 아닌 https 상에서는 해당 값이 암호화되어 날아감.
                //Authorization에 토큰을 넣는 방식을 사용. 토큰이 설령 노출되더라도 이 자체가 id, password가 아니기 때문에 어느정도 안전.
                //이 방식이 Bearer 방식.
                //즉, Basic : id, pw, Bearer: token
                //token은 유효시간이 있기 때문에 노출되어도 만료되면 안전.
                //token = jwt
                .httpBasic().disable()
                .apply(new MyCustomDs1())//커스텀 필터 등록.
                .and()
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();

        return http.build();
    }

    public class MyCustomDs1 extends AbstractHttpConfigurer<MyCustomDs1, HttpSecurity>{
        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http    .addFilter(corsFilter)
                    .addFilter(new JwtAuthenticationFilter(authenticationManager))
                    .addFilter(new JwtAuthorizationFilter(authenticationManager, repository));
        }
    }
}
