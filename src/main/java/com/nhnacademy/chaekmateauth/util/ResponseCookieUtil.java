package com.nhnacademy.chaekmateauth.util;

import com.nhnacademy.chaekmateauth.common.config.CookieConfig;
import com.nhnacademy.chaekmateauth.dto.TokenPair;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ResponseCookieUtil {

    public static final String ACCESS_TOKEN_COOKIE_NAME = "accessToken";
    public static final String REFRESH_TOKEN_COOKIE_NAME = "refreshToken";
    private static final String COOKIE_PATH = "/";
    private static final String SAME_SITE = "Lax";

    private final CookieConfig cookieConfig;
    private final JwtTokenProvider jwtTokenProvider;


    // AccessToken 쿠키 생성
    public ResponseCookie createAccessTokenCookie(String accessToken) {
        return ResponseCookie.from(ACCESS_TOKEN_COOKIE_NAME, accessToken)
                .httpOnly(true)
                .secure(cookieConfig.isSecureCookie())
                .path(COOKIE_PATH)
                .maxAge(jwtTokenProvider.getAccessTokenExpiration())
                .sameSite(SAME_SITE)
                .build();
    }

    // RefreshToken 쿠키 생성
    public ResponseCookie createRefreshTokenCookie(String refreshToken) {
        return ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, refreshToken)
                .httpOnly(true)
                .secure(cookieConfig.isSecureCookie())
                .path(COOKIE_PATH)
                .maxAge(jwtTokenProvider.getRefreshTokenExpiration())
                .sameSite(SAME_SITE)
                .build();
    }

    // AccessToken 쿠키를 HttpServletResponse에 추가
    public void addAccessTokenCookie(HttpServletResponse response, String accessToken) {
        ResponseCookie cookie = createAccessTokenCookie(accessToken);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    // RefreshToken 쿠키를 HttpServletResponse에 추가
    public void addRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        ResponseCookie cookie = createRefreshTokenCookie(refreshToken);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    // TokenPair를 받아서 AccessToken과 RefreshToken 쿠키를 모두 HttpServletResponse에 추가
    public void addTokenCookies(HttpServletResponse response, TokenPair tokenPair) {
        addAccessTokenCookie(response, tokenPair.accessToken());
        addRefreshTokenCookie(response, tokenPair.refreshToken());
    }

}

