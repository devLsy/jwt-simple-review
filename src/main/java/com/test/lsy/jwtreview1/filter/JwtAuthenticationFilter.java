package com.test.lsy.jwtreview1.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.test.lsy.jwtreview1.auth.PrincipalDetails;
import com.test.lsy.jwtreview1.model.User;
import com.test.lsy.jwtreview1.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
// 토큰 생성 및 전달
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청시 호출되는 매서드
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        log.info("로그인 요청 왔음~~~");
        try {
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
//            log.info("user :: {}", user);

            // 토큰 객체 생성
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            Authentication authenticated = authenticationManager.authenticate(authenticationToken);
            return authenticated;

        } catch(IOException e) {
          e.printStackTrace();
        }
        return null;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
    log.info("인증되었음~~~~");
    PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
    // JwtTokenUtil을 사용하여 JWT 토큰 생성
    String jwtToken = JwtUtil.createToken(principalDetails);
    // 응답 헤더에 토큰 추가
    response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
