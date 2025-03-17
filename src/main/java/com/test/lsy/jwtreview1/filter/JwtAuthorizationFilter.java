package com.test.lsy.jwtreview1.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.test.lsy.jwtreview1.auth.PrincipalDetails;
import com.test.lsy.jwtreview1.jwt.JwtProperties;
import com.test.lsy.jwtreview1.model.User;
import com.test.lsy.jwtreview1.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// 토큰 검증
@Slf4j
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private UserRepository repository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);
//        log.info("jwtHeader :: {}", jwtHeader);

        if(jwtHeader == null || !jwtHeader.startsWith(JwtProperties.HEADER_STRING)) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace("Bearer ", "");

        String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build()
                .verify(jwtToken)
                .getClaim("username")
                .asString();

        if(username != null) {
            log.info("정상 서명됨~");
            User findUser = repository.findByUsername(username);
            PrincipalDetails principalDetails = new PrincipalDetails(findUser);

            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
    }
}
