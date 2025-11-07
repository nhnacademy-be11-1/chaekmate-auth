package com.nhnacademy.chaekmateauth;

import com.nhnacademy.chaekmateauth.common.properties.JwtProperties;
import com.nhnacademy.chaekmateauth.dto.TokenPair;
import com.nhnacademy.chaekmateauth.exception.AuthErrorCode;
import com.nhnacademy.chaekmateauth.exception.AuthException;
import com.nhnacademy.chaekmateauth.util.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.test.context.ActiveProfiles;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.crypto.SecretKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ActiveProfiles("test")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT) // 사용되지 않는 stubbing 예외 X
@SuppressWarnings("NonAsciiCharacters")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class JwtTokenProviderTest {

    @Mock
    private JwtProperties jwtProperties;

    @Mock
    private JwtProperties.AccessToken accessToken;

    @Mock
    private JwtProperties.RefreshToken refreshToken;

    @InjectMocks
    private JwtTokenProvider jwtTokenProvider;

    private static final String TEST_SECRET_KEY = "randomSecretKeyForJwtTokenProviderTestingHmacSha256Algorithm123456789";
    private static final Long DEFAULT_ACCESS_EXPIRATION = 3600L;
    private static final Long DEFAULT_REFRESH_EXPIRATION = 604800L;

    @BeforeEach
    void setUp() {
        when(jwtProperties.getSecret()).thenReturn(TEST_SECRET_KEY);
        when(jwtProperties.getAccess()).thenReturn(accessToken);
        when(jwtProperties.getRefresh()).thenReturn(refreshToken);
        when(accessToken.getExp()).thenReturn(DEFAULT_ACCESS_EXPIRATION);
        when(refreshToken.getExp()).thenReturn(DEFAULT_REFRESH_EXPIRATION);
    }

    // 만료된 토큰 생성해주는 메서드
    private String createExpiredToken() {
        SecretKey secretKey = Keys.hmacShaKeyFor(TEST_SECRET_KEY.getBytes(StandardCharsets.UTF_8));
        Date now = new Date();
        Date expiredAt = new Date(now.getTime() - 1000);

        return Jwts.builder()
                .subject("123")
                .issuedAt(new Date(now.getTime() - 3600000))
                .expiration(expiredAt)
                .signWith(secretKey)
                .compact();
    }

    // 다른 시크릿 키 생성해주는 메서드
    private JwtTokenProvider createOtherProvider() {
        JwtProperties otherProperties = new JwtProperties();
        otherProperties.setSecret("DifferentSecretKey_AtLeast_64bytes_ForHMACSHA256Algorithm_Different");

        JwtProperties.AccessToken otherAccessToken = new JwtProperties.AccessToken();
        otherAccessToken.setExp(DEFAULT_ACCESS_EXPIRATION);
        otherProperties.setAccess(otherAccessToken);

        JwtProperties.RefreshToken otherRefreshToken = new JwtProperties.RefreshToken();
        otherRefreshToken.setExp(DEFAULT_REFRESH_EXPIRATION);
        otherProperties.setRefresh(otherRefreshToken);

        return new JwtTokenProvider(otherProperties);
    }

    @Test
    void Access_토큰_생성_성공() {
        Long memberId = 123L;

        String token = jwtTokenProvider.createAccessToken(memberId, JwtTokenProvider.getTypeMember());

        assertThat(token)
                .isNotNull()
                .contains(".");

        Claims claims = jwtTokenProvider.parseToken(token);

        assertThat(claims.getSubject()).isEqualTo(String.valueOf(memberId));
        assertThat(claims.getExpiration()).isNotNull();
    }

    @Test
    void Refresh_토큰_생성_성공() {
        Long memberId = 456L;

        String token = jwtTokenProvider.createRefreshToken(memberId, JwtTokenProvider.getTypeMember());
        Claims claims = jwtTokenProvider.parseToken(token);

        assertThat(claims.getSubject()).isEqualTo(String.valueOf(memberId));
        assertThat(claims.get("type", String.class)).isEqualTo("refresh");
    }

    @Test
    void 토큰_페어_생성_성공() {
        Long memberId = 789L;

        TokenPair tokenPair = jwtTokenProvider.createTokenPair(memberId, JwtTokenProvider.getTypeMember());

        assertThat(tokenPair.accessToken()).isNotEmpty();
        assertThat(tokenPair.refreshToken()).isNotEmpty();

        Claims accessClaims = jwtTokenProvider.parseToken(tokenPair.accessToken());
        Claims refreshClaims = jwtTokenProvider.parseToken(tokenPair.refreshToken());

        assertThat(accessClaims.getSubject()).isEqualTo(String.valueOf(memberId));
        assertThat(refreshClaims.getSubject()).isEqualTo(String.valueOf(memberId));
        assertThat(refreshClaims.get("type", String.class)).isEqualTo("refresh");
    }

    @Test
    void 유효한_토큰_검증_성공() {
        Long memberId = 123L;
        String token = jwtTokenProvider.createAccessToken(memberId, JwtTokenProvider.getTypeMember());

        boolean isValid = jwtTokenProvider.validateToken(token);

        assertThat(isValid).isTrue();
    }

    // null, 빈문자열, 잘못된 형식 테스트용
    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "invalid.token.format"})
    void 유효하지_않은_토큰_검증_실패(String invalidToken) {
        boolean isValid = jwtTokenProvider.validateToken(invalidToken);
        assertThat(isValid).isFalse();
    }

    @Test
    void 만료된_토큰_검증_실패() {
        String expiredToken = createExpiredToken();

        boolean isValid = jwtTokenProvider.validateToken(expiredToken);

        assertThat(isValid).isFalse();
    }

    @Test
    void 토큰_파싱_성공() {
        Long memberId = 123L;
        String token = jwtTokenProvider.createAccessToken(memberId, JwtTokenProvider.getTypeMember());

        Claims claims = jwtTokenProvider.parseToken(token);

        assertThat(claims.getSubject()).isEqualTo(String.valueOf(memberId));
        assertThat(claims.getExpiration()).isNotNull();
    }

    @Test
    void 만료된_토큰_파싱_실패() {
        String expiredToken = createExpiredToken();

        AuthException exception = assertThrows(AuthException.class, () ->
                jwtTokenProvider.parseToken(expiredToken));

        assertThat(exception.getErrorCode()).isEqualTo(AuthErrorCode.TOKEN_EXPIRED);
    }

    @Test
    void 잘못된_형식의_토큰_파싱_실패() {
        AuthException exception = assertThrows(AuthException.class, () ->
                jwtTokenProvider.parseToken("invalid.token.format"));

        assertThat(exception.getErrorCode()).isEqualTo(AuthErrorCode.TOKEN_INVALID);
    }

    @Test
    void 잘못된_서명의_토큰_파싱_실패() {
        JwtTokenProvider otherProvider = createOtherProvider();
        String token = otherProvider.createAccessToken(123L, JwtTokenProvider.getTypeMember());

        AuthException exception = assertThrows(AuthException.class, () ->
                jwtTokenProvider.parseToken(token));

        assertThat(exception.getErrorCode()).isEqualTo(AuthErrorCode.TOKEN_INVALID);
    }

    @Test
    void 토큰에서_memberId_추출_성공() {
        Long memberId = 456L;
        String token = jwtTokenProvider.createAccessToken(memberId, JwtTokenProvider.getTypeMember());

        Long extractedMemberId = jwtTokenProvider.getMemberIdFromToken(token);
        assertThat(extractedMemberId).isEqualTo(memberId);
    }

    @Test
    void 잘못된_토큰에서_memberId_추출_실패() {
        assertThrows(AuthException.class, () ->
                jwtTokenProvider.getMemberIdFromToken("invalid.token.format"));
    }

    @Test
    void 토큰_만료_시간_확인() {
        long beforeCreation = System.currentTimeMillis();
        Long memberId = 123L;
        String token = jwtTokenProvider.createAccessToken(memberId, JwtTokenProvider.getTypeMember());

        Claims claims = jwtTokenProvider.parseToken(token);
        Date expiration = claims.getExpiration();

        long expectedExpiration = beforeCreation + (DEFAULT_ACCESS_EXPIRATION * 1000);
        long difference = Math.abs(expectedExpiration - expiration.getTime());

        assertThat(difference).isLessThan(1000);
    }

    @Test
    void Refresh_토큰_만료_시간이_Access_토큰보다_김() {
        Long memberId = 123L;
        String access = jwtTokenProvider.createAccessToken(memberId, JwtTokenProvider.getTypeMember());
        String refresh = jwtTokenProvider.createRefreshToken(memberId, JwtTokenProvider.getTypeMember());

        Claims accessClaims = jwtTokenProvider.parseToken(access);
        Claims refreshClaims = jwtTokenProvider.parseToken(refresh);

        assertThat(refreshClaims.getExpiration()).isAfter(accessClaims.getExpiration());
    }

    @Test
    void Refresh_토큰인지_확인_성공() {
        Long memberId = 123L;
        String refreshTokenStr = jwtTokenProvider.createRefreshToken(memberId, JwtTokenProvider.getTypeMember());
        assertThat(jwtTokenProvider.isRefreshToken(refreshTokenStr)).isTrue();
    }

    @Test
    void Access_토큰은_Refresh_토큰이_아님() {
        Long memberId = 123L;
        String accessTokenStr = jwtTokenProvider.createAccessToken(memberId, JwtTokenProvider.getTypeMember());
        assertThat(jwtTokenProvider.isRefreshToken(accessTokenStr)).isFalse();
    }

    @Test
    void Refresh_토큰_검증_성공() {
        Long memberId = 123L;
        String refreshTokenStr = jwtTokenProvider.createRefreshToken(memberId, JwtTokenProvider.getTypeMember());
        assertThat(jwtTokenProvider.validateRefreshToken(refreshTokenStr)).isTrue();
    }

    @Test
    void Access_토큰은_Refresh_토큰_검증_실패() {
        Long memberId = 123L;
        String accessTokenStr = jwtTokenProvider.createAccessToken(memberId, JwtTokenProvider.getTypeMember());
        assertThat(jwtTokenProvider.validateRefreshToken(accessTokenStr)).isFalse();
    }
}