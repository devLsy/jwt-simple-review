package com.test.lsy.jwtreview1.config.security;

import com.test.lsy.jwtreview1.filter.JwtAuthenticationFilter;
import com.test.lsy.jwtreview1.filter.JwtAuthorizationFilter;
import com.test.lsy.jwtreview1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final UserRepository repository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                // 세션 사용하지 않겠다.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilter(corsFilter)
                // form login 사용하지 않겠다.
                .formLogin(form -> form.disable())
                // http 기본 인증 방식 사용하지 않겠다.
                .httpBasic(basic -> basic.disable())
                // JWT 필터(토큰 생성)
                .addFilter(new JwtAuthenticationFilter(authenticationManager()))
                // JWT 토큰 인증
                .addFilterBefore(new JwtAuthorizationFilter(), JwtAuthenticationFilter.class)
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers("/api/v1/user/**")
                                .hasAnyRole("USER", "MANAGER", "ADMIN")
                            .requestMatchers("/api/v1/manager/**")
                                .hasAnyRole("MANAGER", "ADMIN")
                            .requestMatchers("/api/v1/admin/**")
                                .hasAnyRole("ADMIN")
                                .anyRequest().permitAll()
                );
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager(); // 수정
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
