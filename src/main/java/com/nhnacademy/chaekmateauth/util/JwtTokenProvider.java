package com.nhnacademy.chaekmateauth.util;

import com.nhnacademy.chaekmateauth.common.properties.JwtProperties;
import com.nhnacademy.chaekmateauth.dto.TokenPair;
import com.nhnacademy.chaekmateauth.exception.AuthErrorCode;
import com.nhnacademy.chaekmateauth.exception.AuthException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private static final String CLAIM_TYPE = "type";
    private static final String TYPE_REFRESH = "refresh";
    private static final String TYPE_MEMBER = "member";
    private static final String TYPE_ADMIN = "admin";
    private static final String CLAIM_USER_TYPE = "userType";

    // 설정 주입
    private final JwtProperties jwtProperties;

    // HMAC-SHA256 Secret Key 반환
    private SecretKey getSecretKey() {
        String secret = jwtProperties.getSecret();
        byte[] keyBytes;
        try {
            keyBytes = Decoders.BASE64.decode(secret);
        } catch (IllegalArgumentException ignore) {
            keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String createAccessToken(Long id, String userType) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + jwtProperties.getAccess().getExp() * 1000); // 밀리초니까 1000곱해서 초로 맞춤

        return Jwts.builder()
                .subject(String.valueOf(id))
                .claim(CLAIM_USER_TYPE, userType)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(getSecretKey())
                .compact();
    }

    public String createRefreshToken(Long id, String userType) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + jwtProperties.getRefresh().getExp() * 1000);

        return Jwts.builder()
                .subject(String.valueOf(id))
                .claim(CLAIM_TYPE, TYPE_REFRESH)
                .claim(CLAIM_USER_TYPE, userType)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(getSecretKey())
                .compact();
    }

    public TokenPair createTokenPair(Long id, String userType) {
        String accessToken = createAccessToken(id, userType);
        String refreshToken = createRefreshToken(id, userType);
        return new TokenPair(accessToken, refreshToken);
    }


    public boolean validateToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }

        try {
            Jwts.parser()
                    .verifyWith(getSecretKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public Claims parseToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            throw new AuthException(AuthErrorCode.TOKEN_INVALID);
        }
        try{
            return Jwts.parser()
                    .verifyWith(getSecretKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new AuthException(AuthErrorCode.TOKEN_EXPIRED, e);
        } catch (MalformedJwtException | SignatureException e) {
            throw new AuthException(AuthErrorCode.TOKEN_INVALID, e);
        } catch (Exception e) {
            throw new AuthException(AuthErrorCode.TOKEN_PARSE_FAILED, e);
        }
    }

    public Long getMemberIdFromToken(String token) {
        Claims claims = parseToken(token);
        return Long.parseLong(claims.getSubject());
    }

    public String getUserTypeFromToken(String token) {
        Claims claims = parseToken(token);
        return claims.get(CLAIM_USER_TYPE, String.class);
    }

    public boolean isRefreshToken(String token) {
        try {
            Claims claims = parseToken(token);
            String type = claims.get(CLAIM_TYPE, String.class);
            return TYPE_REFRESH.equals(type);
        } catch (AuthException e) {
            return false;
        }
    }

    public boolean validateRefreshToken(String token) {
        if (!validateToken(token)) {
            return false;
        }
        return isRefreshToken(token);
    }

    public Long getAccessTokenExpiration() {
        return jwtProperties.getAccess().getExp();
    }

    public Long getRefreshTokenExpiration() {
        return jwtProperties.getRefresh().getExp();
    }

    public static String getTypeMember() {
        return TYPE_MEMBER;
    }

    public static String getTypeAdmin() {
        return TYPE_ADMIN;
    }
}
