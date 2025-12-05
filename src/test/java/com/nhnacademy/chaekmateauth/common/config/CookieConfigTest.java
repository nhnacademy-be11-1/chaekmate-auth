package com.nhnacademy.chaekmateauth.common.config;

import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

@ActiveProfiles("test")
@SuppressWarnings("NonAsciiCharacters")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class CookieConfigTest {

    @Test
    void isSecureCookie_dev_프로파일() {
        CookieConfig cookieConfig = new CookieConfig();
        ReflectionTestUtils.setField(cookieConfig, "activeProfile", "dev");

        boolean result = cookieConfig.isSecureCookie();

        assertThat(result).isFalse();
    }

    @Test
    void isSecureCookie_prod_프로파일() {
        CookieConfig cookieConfig = new CookieConfig();
        ReflectionTestUtils.setField(cookieConfig, "activeProfile", "prod");

        boolean result = cookieConfig.isSecureCookie();

        assertThat(result).isTrue();
    }

    @Test
    void isSecureCookie_기타_프로파일() {
        CookieConfig cookieConfig = new CookieConfig();
        ReflectionTestUtils.setField(cookieConfig, "activeProfile", "test");

        boolean result = cookieConfig.isSecureCookie();

        assertThat(result).isTrue();
    }
}

