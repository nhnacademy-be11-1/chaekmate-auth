package com.nhnacademy.chaekmateauth.util;

import com.nhnacademy.chaekmateauth.common.config.CookieConfig;
import com.nhnacademy.chaekmateauth.common.properties.JwtProperties;
import com.nhnacademy.chaekmateauth.dto.TokenPair;
import java.lang.reflect.Method;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;

@ActiveProfiles("test")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("NonAsciiCharacters")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class ResponseCookieUtilTest {

    @Mock
    private CookieConfig cookieConfig;

    @Mock
    private JwtProperties jwtProperties;

    @Mock
    private JwtProperties.AccessToken accessToken;

    @Mock
    private JwtProperties.RefreshToken refreshToken;

    private ResponseCookieUtil responseCookieUtil;

    private static final String TEST_SECRET_KEY = "randomSecretKeyForJwtTokenProviderTestingHmacSha256Algorithm123456789";
    private static final Long DEFAULT_ACCESS_EXPIRATION = 3600L;
    private static final Long DEFAULT_REFRESH_EXPIRATION = 604800L;

    @BeforeEach
    void setUp() throws Exception {
        given(jwtProperties.getSecret()).willReturn(TEST_SECRET_KEY);
        given(jwtProperties.getAccess()).willReturn(accessToken);
        given(jwtProperties.getRefresh()).willReturn(refreshToken);
        given(accessToken.getExp()).willReturn(DEFAULT_ACCESS_EXPIRATION);
        given(refreshToken.getExp()).willReturn(DEFAULT_REFRESH_EXPIRATION);

        MemberIdEncryptor memberIdEncryptor = new MemberIdEncryptor(jwtProperties);
        JwtTokenProvider jwtTokenProvider = new JwtTokenProvider(jwtProperties, memberIdEncryptor);

        Method initMethod = JwtTokenProvider.class.getDeclaredMethod("init");
        initMethod.setAccessible(true);
        initMethod.invoke(jwtTokenProvider);

        responseCookieUtil = new ResponseCookieUtil(cookieConfig, jwtTokenProvider);
    }

    @Test
    void AccessToken_쿠키_생성_성공() {
        String accessTokenValue = "test-access-token";
        given(cookieConfig.isSecureCookie()).willReturn(false);

        ResponseCookie cookie = responseCookieUtil.createAccessTokenCookie(accessTokenValue);

        assertThat(cookie.getName()).isEqualTo(ResponseCookieUtil.ACCESS_TOKEN_COOKIE_NAME);
        assertThat(cookie.getValue()).isEqualTo(accessTokenValue);
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.getMaxAge().getSeconds()).isEqualTo(DEFAULT_ACCESS_EXPIRATION);
    }

    @Test
    void RefreshToken_쿠키_생성_성공() {
        String refreshTokenValue = "test-refresh-token";
        given(cookieConfig.isSecureCookie()).willReturn(false);

        ResponseCookie cookie = responseCookieUtil.createRefreshTokenCookie(refreshTokenValue);

        assertThat(cookie.getName()).isEqualTo(ResponseCookieUtil.REFRESH_TOKEN_COOKIE_NAME);
        assertThat(cookie.getValue()).isEqualTo(refreshTokenValue);
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.getMaxAge().getSeconds()).isEqualTo(DEFAULT_REFRESH_EXPIRATION);
    }

    @Test
    void secure_쿠키_생성_성공() {
        String accessTokenValue = "test-access-token";
        given(cookieConfig.isSecureCookie()).willReturn(true);

        ResponseCookie cookie = responseCookieUtil.createAccessTokenCookie(accessTokenValue);

        assertThat(cookie.isSecure()).isTrue();
    }

    @Test
    void AccessToken_쿠키를_HttpServletResponse에_추가_성공() {
        String accessTokenValue = "test-access-token";
        MockHttpServletResponse response = new MockHttpServletResponse();
        given(cookieConfig.isSecureCookie()).willReturn(false);

        responseCookieUtil.addAccessTokenCookie(response, accessTokenValue);

        String setCookieHeader = response.getHeader(HttpHeaders.SET_COOKIE);
        assertThat(setCookieHeader)
                .isNotNull()
                .contains(ResponseCookieUtil.ACCESS_TOKEN_COOKIE_NAME)
                .contains(accessTokenValue);
    }

    @Test
    void RefreshToken_쿠키를_HttpServletResponse에_추가_성공() {
        String refreshTokenValue = "test-refresh-token";
        MockHttpServletResponse response = new MockHttpServletResponse();
        given(cookieConfig.isSecureCookie()).willReturn(false);

        responseCookieUtil.addRefreshTokenCookie(response, refreshTokenValue);

        String setCookieHeader = response.getHeader(HttpHeaders.SET_COOKIE);
        assertThat(setCookieHeader)
                .isNotNull()
                .contains(ResponseCookieUtil.REFRESH_TOKEN_COOKIE_NAME)
                .contains(refreshTokenValue);
    }

    @Test
    void TokenPair_쿠키를_모두_추가_성공() {
        String accessTokenValue = "test-access-token";
        String refreshTokenValue = "test-refresh-token";
        TokenPair tokenPair = new TokenPair(accessTokenValue, refreshTokenValue);
        MockHttpServletResponse response = new MockHttpServletResponse();
        given(cookieConfig.isSecureCookie()).willReturn(false);

        responseCookieUtil.addTokenCookies(response, tokenPair);

        assertThat(response.getHeaders(HttpHeaders.SET_COOKIE)).hasSize(2);
    }
}
