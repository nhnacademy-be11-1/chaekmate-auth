package com.nhnacademy.chaekmateauth.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;

@ActiveProfiles("test")
@SuppressWarnings("NonAsciiCharacters")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class CookieUtilTest {

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void 쿠키에서_accessToken_추출_성공() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("accessToken", "test-token-value"));

        String token = CookieUtil.extractAccessTokenFromCookie(request);

        assertThat(token).isEqualTo("test-token-value");
    }

    @Test
    void 쿠키가_없을_때_null_반환() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        String token = CookieUtil.extractAccessTokenFromCookie(request);

        assertThat(token).isNull();
    }

    @Test
    void accessToken_쿠키가_없을_때_null_반환() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("otherCookie", "value"));

        String token = CookieUtil.extractAccessTokenFromCookie(request);

        assertThat(token).isNull();
    }

    @Test
    void RequestContextHolder에서_accessToken_추출_성공() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("accessToken", "test-token"));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        String token = CookieUtil.extractAccessTokenFromCookie();

        assertThat(token).isEqualTo("test-token");
    }

    @Test
    void RequestContextHolder가_null일_때_null_반환() {
        RequestContextHolder.setRequestAttributes(null);

        String token = CookieUtil.extractAccessTokenFromCookie();

        assertThat(token).isNull();
    }

    @Test
    void null_request에서_추출_시_null_반환() {
        String token = CookieUtil.extractAccessTokenFromCookie((HttpServletRequest) null);

        assertThat(token).isNull();
    }
}
