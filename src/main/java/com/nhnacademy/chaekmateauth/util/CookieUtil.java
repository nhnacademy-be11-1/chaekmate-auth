package com.nhnacademy.chaekmateauth.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

public class CookieUtil {

    private static final String ACCESS_TOKEN_COOKIE_NAME = "accessToken";

    // 현재 요청의 쿠키에서 accessToken을 추출함
    public static String extractAccessTokenFromCookie() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

        if(attributes == null) {
            return null;
        }

        HttpServletRequest request = attributes.getRequest();
        return extractAccessTokenFromCookie(request);
    }

    // HttpServletRequest에서 accessToken을 추출함
    public static String extractAccessTokenFromCookie(HttpServletRequest request) {
        if(request == null) {
            return null;
        }
        Cookie[] cookies = request.getCookies();
        if(cookies == null) {
            return null;
        }

        for(Cookie cookie : cookies) {
            if(ACCESS_TOKEN_COOKIE_NAME.equals(cookie.getName())){
                return cookie.getValue();
            }
        }
        return null;
    }
}
