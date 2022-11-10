package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

import static com.cos.jwt.config.jwt.JwtProperties.*;

//스프링 시큐리티의 UsernamePasswordAuthenticationFilter는
// /login 경로로 username, password를 post로 request시 동작
//따라서 UsernamePasswordAuthenticationFilter을 상속받는 이 필터를 시큐리티 필터체인에
//명시적으로 등록해준다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // login request시 로그인 시도를 위해서 실행되는 함수
    // login request가 오면 usernamepasswordauthenticationfilter가 요청을 가로채고 attemptAuthentication 메서드가 실행된다
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFIlter : 로그인 시도중");
        //Process
            //1. username, password 받아서 정상인지 로그인 시도.
            //2. authenticationManager로 로그인 시도를 하면
            //3. PrincipalDetailsService의 loadByUsername이 호출됨.
            //4. loadbyusername에서 principaldetails를 정상적으로 return하면 security session에 해당 객체를 담고
            //5. jwt 토큰을 만들어서 응답해주면 된다.
            //++ jwt 쓸건데 principalDetails를 굳이 세션에 담는 이유는 securityconfig에 정의된 filterchain에서
            //  antmatcher를 통해 권한관리를 하는데, 세션에 담지 않으면 그것이 불가능
            // 반대로 말하면 권한 관리를 할 필요가 없으면 세션에 담지 않아도 된다.


        try {
            //1.
//            BufferedReader br = request.getReader();
//            String input = null;
//            while((input = br.readLine()) != null){
//                System.out.println(input);
            //contenttype이 x-www-form-urlencoded인 경우 io를 통해서 String 형태로 읽어들일 수 있지만
            //만약 json타입으로 요청이 왔을 때 ObjectMapper를 이용하면 해당 객체에 바인드할 수 있음.

            //2.
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            //security 기본 설정을 이용하면 원래 자동으로 토큰을 만들어주지만, disable했기 때문에 직접 만들어준다.
            UsernamePasswordAuthenticationToken authenticationToken
                    = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            //authenticationManager에 token 객체를 담아서 던져주고,
            //이 때 PrincipalDetailsService의 loadbyUsername이 실행된다.
            //그 후 정상이면 authentication이 리턴된다.
            //정상적이란 것은 DB에 있는 username과 passoword가 일치한다는 것.
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            //security1 프로젝트에서 설명했듯이,
            //로그인 진행이 완료되면 시큐리티는 자신의 session을 만든다.(SecurityContextHolder)
            //spring seuciry session 영역에는 들어갈 수 있는 Object 타입이 정해져있는데,
            // authentication과, 그 안에는 유저 정보인 principaldetails 객체가 담긴다.
            // 여기서 principalDetails는 UserDetails 혹은 OAuth2User 타입의 커스텀 객체.
            PrincipalDetails principalDetails = (PrincipalDetails)  authentication.getPrincipal();
            //principaldetails객체에 로그인 정보가 잘 담겼는지 확인 후
            System.out.println(principalDetails.getUser().getUsername());
            //정상적이라면 authentication 객체를 session영역에 저장하기 위해 authentication을 리턴해준다.
            //즉, authentication이 return될 때 session 영역에 담긴다.(이 authentication으로 security가 권한관리를 해줌)
            //또한 위에서 기술했다싶이, JWT 토큰을 사용하기 때문에 유저 정보를 세션에 가지고있을 필요는 없음.
            //단지 security가 권한 처리를 해주는데 그 과정에서 필요하기 때문에 return하여 세션에 넣는 것임.
            //이 authentication에는 로그인시의 정보가 담긴다
            return authentication;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    //attemptAuthentication 메서드가 종료되고 인증이 정상적으로 되었으면, successfulAuthenticaion이 실행된다.
    //여기서 JWT 토큰을 만들어서 request요청한 사용자에게 JWT 토큰을 response해준다.

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행. 인증 완료되었음.");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+(EXPIRATION_TIME)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(SECRET));

        response.addHeader(HEADER_STRING, TOKEN_PREFIX+jwtToken);
    }
}
