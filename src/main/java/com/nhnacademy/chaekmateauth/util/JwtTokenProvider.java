package com.nhnacademy.chaekmateauth.util;

import com.nhnacademy.chaekmateauth.common.properties.JwtProperties;
import com.nhnacademy.chaekmateauth.dto.TokenPair;
import com.nhnacademy.chaekmateauth.exception.AuthErrorCode;
import com.nhnacademy.chaekmateauth.exception.AuthException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private static final String TYPE_ACCESS = "access";
    private static final String TYPE_REFRESH = "refresh";
    private static final String TYPE_MEMBER = "member";
    private static final String TYPE_ADMIN = "admin";

    private static final String CLAIM_ROLE = "r";
    private static final String CLAIM_TOKEN_TYPE = "t";

    // 설정 주입
    private final JwtProperties jwtProperties;
    private final MemberIdEncryptor memberIdEncryptor;

    private String hashedMember;
    private String hashedAdmin;
    private String hashedAccess;
    private String hashedRefresh;

    // Bean 생성 후 해시값 초기화
    @PostConstruct
    private void init() {
        // JWT secret을 salt로 사용하여 해시 생성
        String salt = jwtProperties.getSecret().substring(0, Math.min(16, jwtProperties.getSecret().length()));
        this.hashedMember = hashValue(TYPE_MEMBER, salt);
        this.hashedAdmin = hashValue(TYPE_ADMIN, salt);
        this.hashedAccess = hashValue(TYPE_ACCESS, salt);
        this.hashedRefresh = hashValue(TYPE_REFRESH, salt);
    }

    // SHA-256 해시 생성
    private String hashValue(String value, String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String input = value + salt; // hash로 바꾸려는 값
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8)); // 입력 UTF-8로 바꾼 다음에 해시해서 32바이트 배열 반환

            // 32자리 16진수 문자열로 변환
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b); // 바이트를 0~255범위의 양수로 변환
                if (hex.length() == 1) {
                    hexString.append('0'); // 한자리면 앞에 0 추가
                }
                hexString.append(hex);
            }
            String hexResult = hexString.toString();
            return hexResult.substring(0, 32); // 32자리만 사용
        } catch (NoSuchAlgorithmException e) {
            throw new AuthException(AuthErrorCode.INTERNAL_SERVER_ERROR, e);
        }
    }

    // HMAC-SHA256 Secret Key 반환
    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    public String createAccessToken(Long id, String userType) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + jwtProperties.getAccess().getExp() * 1000); // 밀리초니까 1000곱해서 초로 맞춤

        // memberId 암호화
        String encryptedId = memberIdEncryptor.encryptMemberId(id);

        // role 해시값 선택
        String hashedRole = TYPE_ADMIN.equals(userType) ? hashedAdmin : hashedMember;

        return Jwts.builder()
                .subject(encryptedId)  // 암호화된 memberId
                .claim(CLAIM_ROLE, hashedRole)  // 해시된 role
                .claim(CLAIM_TOKEN_TYPE, hashedAccess)  // 해시된 token type
                .issuedAt(now)
                .expiration(expiration)
                .signWith(getSecretKey())
                .compact();
    }

    public String createRefreshToken(Long id, String userType) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + jwtProperties.getRefresh().getExp() * 1000);

        // memberId 암호화
        String encryptedId = memberIdEncryptor.encryptMemberId(id);

        // role 해시값 선택
        String hashedRole = TYPE_ADMIN.equals(userType) ? hashedAdmin : hashedMember;

        return Jwts.builder()
                .subject(encryptedId)  // 암호화된 memberId
                .claim(CLAIM_ROLE, hashedRole)  // 해시된 role
                .claim(CLAIM_TOKEN_TYPE, hashedRefresh)  // 해시된 token type
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
        String encryptedId = claims.getSubject();
        return memberIdEncryptor.decryptMemberId(encryptedId);
    }

    public String getUserTypeFromToken(String token) {
        Claims claims = parseToken(token);
        // 해시된 role 추출
        String hashedRole = claims.get(CLAIM_ROLE, String.class);
        if (hashedRole == null) {
            throw new AuthException(AuthErrorCode.TOKEN_INVALID);
        }

        // 해시값 비교
        if (hashedAdmin.equals(hashedRole)) {
            return TYPE_ADMIN;
        } else if (hashedMember.equals(hashedRole)) {
            return TYPE_MEMBER;
        }
        throw new AuthException(AuthErrorCode.TOKEN_INVALID);
    }

    public boolean isRefreshToken(String token) {
        try {
            Claims claims = parseToken(token);
            // 해시된 token type 추출
            String hashedTokenType = claims.get(CLAIM_TOKEN_TYPE, String.class);
            if (hashedTokenType == null) {
                return false;
            }

            return TYPE_REFRESH.equals(hashedTokenType);
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
