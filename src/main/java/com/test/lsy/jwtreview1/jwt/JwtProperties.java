package com.test.lsy.jwtreview1.jwt;

public class JwtProperties {
    public static final String SECRET = "비밀의존";
    public static final int EXPIRATION_TIME = 864000000; // 10일 (1/1000초)
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";
}
