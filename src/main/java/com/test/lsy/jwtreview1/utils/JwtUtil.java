package com.test.lsy.jwtreview1.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.test.lsy.jwtreview1.auth.PrincipalDetails;
import com.test.lsy.jwtreview1.jwt.JwtProperties;

import java.util.Date;

public class JwtUtil {

    public static String createToken(PrincipalDetails principalDetails) {
        return JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(JwtProperties.EXPIRATION_TIME))
                .withClaim("id", principalDetails.getUser().getId()) // 사용자 ID
                .withClaim("username", principalDetails.getUser().getUsername()) // 사용자 이름
                .sign(Algorithm.HMAC512(JwtProperties.SECRET)); // 암호화 키
    }
}
