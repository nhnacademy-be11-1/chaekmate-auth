package com.nhnacademy.chaekmateauth.controller;

import com.nhnacademy.chaekmateauth.dto.TokenPair;
import com.nhnacademy.chaekmateauth.dto.request.DormantVerificationRequest;
import com.nhnacademy.chaekmateauth.dto.request.LoginRequest;
import com.nhnacademy.chaekmateauth.dto.response.LoginResponse;
import com.nhnacademy.chaekmateauth.dto.response.LogoutResponse;
import com.nhnacademy.chaekmateauth.dto.response.MemberInfoResponse;
import com.nhnacademy.chaekmateauth.dto.response.PaycoAuthorizationResponse;
import com.nhnacademy.chaekmateauth.dto.response.PaycoTempInfoResponse;
import com.nhnacademy.chaekmateauth.entity.Admin;
import com.nhnacademy.chaekmateauth.entity.Member;
import com.nhnacademy.chaekmateauth.exception.AuthErrorCode;
import com.nhnacademy.chaekmateauth.exception.AuthException;
import com.nhnacademy.chaekmateauth.repository.AdminRepository;
import com.nhnacademy.chaekmateauth.repository.MemberRepository;
import com.nhnacademy.chaekmateauth.service.AuthService;
import com.nhnacademy.chaekmateauth.util.JwtTokenProvider;
import com.nhnacademy.chaekmateauth.util.ResponseCookieUtil;
import jakarta.servlet.http.HttpServletResponse;
import java.lang.reflect.Constructor;
import java.time.Duration;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.never;
import static org.mockito.BDDMockito.then;
import static org.mockito.BDDMockito.willDoNothing;

@ActiveProfiles("test")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("NonAsciiCharacters")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class AuthControllerTest {

    @Mock
    private AuthService authService;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private ResponseCookieUtil responseCookieUtil;

    @Mock
    private RedisTemplate<String, String> redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @Mock
    private MemberRepository memberRepository;

    @Mock
    private AdminRepository adminRepository;

    @InjectMocks
    private AuthController authController;

    private HttpServletResponse response;
    private Member member;
    private Admin admin;

    @BeforeEach
    void setUp() throws Exception {
        response = new MockHttpServletResponse();

        Constructor<Member> memberConstructor = Member.class.getDeclaredConstructor();
        memberConstructor.setAccessible(true);
        member = memberConstructor.newInstance();
        ReflectionTestUtils.setField(member, "id", 1L);
        ReflectionTestUtils.setField(member, "name", "테스트유저");

        Constructor<Admin> adminConstructor = Admin.class.getDeclaredConstructor();
        adminConstructor.setAccessible(true);
        admin = adminConstructor.newInstance();
        ReflectionTestUtils.setField(admin, "id", 1L);

        given(redisTemplate.opsForValue()).willReturn(valueOperations);
    }

    @Test
    void 회원_로그인_성공() {
        LoginRequest request = new LoginRequest("testuser", "password");
        TokenPair tokenPair = new TokenPair("access-token", "refresh-token");

        given(authService.memberLogin(request)).willReturn(tokenPair);
        given(jwtTokenProvider.getMemberIdFromToken("access-token")).willReturn(1L);
        given(jwtTokenProvider.getRefreshTokenExpiration()).willReturn(604800L);
        willDoNothing().given(responseCookieUtil).addTokenCookies(any(HttpServletResponse.class), eq(tokenPair));

        ResponseEntity<LoginResponse> result = authController.memberLogin(request, response);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().message()).isEqualTo("로그인 성공");
        then(responseCookieUtil).should().addTokenCookies(any(HttpServletResponse.class), eq(tokenPair));
        then(redisTemplate.opsForValue()).should().set(anyString(), eq("refresh-token"), any(Duration.class));
    }

    @Test
    void 관리자_로그인_성공() {
        LoginRequest request = new LoginRequest("admin", "adminpassword");
        TokenPair tokenPair = new TokenPair("admin-access-token", "admin-refresh-token");

        given(authService.adminLogin(request)).willReturn(tokenPair);
        given(jwtTokenProvider.getMemberIdFromToken("admin-access-token")).willReturn(1L);
        given(jwtTokenProvider.getRefreshTokenExpiration()).willReturn(604800L);
        willDoNothing().given(responseCookieUtil).addTokenCookies(any(HttpServletResponse.class), eq(tokenPair));

        ResponseEntity<LoginResponse> result = authController.adminLogin(request, response);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().message()).isEqualTo("관리자 로그인 성공");
        then(responseCookieUtil).should().addTokenCookies(any(HttpServletResponse.class), eq(tokenPair));
    }

    @Test
    void 회원_정보_조회_성공_Member() {
        String token = "member-token";

        given(jwtTokenProvider.getMemberIdFromToken(token)).willReturn(1L);
        given(jwtTokenProvider.getUserTypeFromToken(token)).willReturn(JwtTokenProvider.getTypeMember());
        given(memberRepository.findById(1L)).willReturn(Optional.of(member));

        ResponseEntity<MemberInfoResponse> result = authController.getMemberInfo(token);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().memberId()).isEqualTo(1L);
        assertThat(result.getBody().name()).isEqualTo("테스트유저");
        assertThat(result.getBody().role()).isEqualTo("USER");
    }

    @Test
    void 회원_정보_조회_성공_Admin() {
        String token = "admin-token";

        given(jwtTokenProvider.getMemberIdFromToken(token)).willReturn(1L);
        given(jwtTokenProvider.getUserTypeFromToken(token)).willReturn(JwtTokenProvider.getTypeAdmin());
        given(adminRepository.findById(1L)).willReturn(Optional.of(admin));

        ResponseEntity<MemberInfoResponse> result = authController.getMemberInfo(token);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().memberId()).isEqualTo(1L);
        assertThat(result.getBody().name()).isEqualTo("admin");
        assertThat(result.getBody().role()).isEqualTo("ADMIN");
    }

    @Test
    void 회원_정보_조회_실패_회원_없음() {
        String token = "member-token";

        given(jwtTokenProvider.getMemberIdFromToken(token)).willReturn(1L);
        given(jwtTokenProvider.getUserTypeFromToken(token)).willReturn(JwtTokenProvider.getTypeMember());
        given(memberRepository.findById(1L)).willReturn(Optional.empty());

        assertThatThrownBy(() -> authController.getMemberInfo(token))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.MEMBER_NOT_FOUND);
    }

    @Test
    void 로그아웃_성공_AccessToken_사용() {
        String accessToken = "valid-access-token";
        String refreshToken = "valid-refresh-token";

        given(jwtTokenProvider.getMemberIdFromToken(accessToken)).willReturn(1L);
        given(redisTemplate.delete(anyString())).willReturn(true);

        ResponseEntity<LogoutResponse> result = authController.logout(accessToken, refreshToken);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().message()).isEqualTo("로그아웃 성공");
        then(redisTemplate).should().delete("refresh:1");
    }

    @Test
    void 로그아웃_성공_RefreshToken_사용() {
        String accessToken = null;
        String refreshToken = "valid-refresh-token";

        given(jwtTokenProvider.getMemberIdFromToken(refreshToken)).willReturn(1L);
        given(redisTemplate.delete(anyString())).willReturn(true);

        ResponseEntity<LogoutResponse> result = authController.logout(accessToken, refreshToken);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().message()).isEqualTo("로그아웃 성공");
        then(redisTemplate).should().delete("refresh:1");
    }

    @Test
    void 로그아웃_성공_토큰_모두_만료() {
        String accessToken = "expired-access-token";
        String refreshToken = "expired-refresh-token";

        given(jwtTokenProvider.getMemberIdFromToken(accessToken)).willThrow(new AuthException(AuthErrorCode.TOKEN_INVALID));
        given(jwtTokenProvider.getMemberIdFromToken(refreshToken)).willThrow(new AuthException(AuthErrorCode.TOKEN_INVALID));

        ResponseEntity<LogoutResponse> result = authController.logout(accessToken, refreshToken);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().message()).isEqualTo("로그아웃 성공");
        then(redisTemplate).should(never()).delete(anyString());
    }

    @Test
    void 토큰_재발급_성공() {
        String refreshToken = "valid-refresh-token";
        TokenPair newTokenPair = new TokenPair("new-access-token", "new-refresh-token");

        given(authService.refreshToken(refreshToken)).willReturn(newTokenPair);
        willDoNothing().given(responseCookieUtil).addTokenCookies(any(HttpServletResponse.class), eq(newTokenPair));

        ResponseEntity<LoginResponse> result = authController.refreshToken(refreshToken, response);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().message()).isEqualTo("토큰 재발급 성공");
        then(responseCookieUtil).should().addTokenCookies(any(HttpServletResponse.class), eq(newTokenPair));
    }

    @Test
    void PAYCO_인증_URL_조회_성공() {
        String authorizationUrl = "https://id.payco.com/oauth2.0/authorize?client_id=test";

        given(authService.getPaycoAuthorizationUrl()).willReturn(authorizationUrl);

        ResponseEntity<PaycoAuthorizationResponse> result = authController.getPaycoAuthorizationUrl();

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().authorizationUrl()).isEqualTo(authorizationUrl);
    }

    @Test
    void PAYCO_콜백_처리_기존_회원() {
        String code = "authorization-code";
        PaycoTempInfoResponse callbackResponse = new PaycoTempInfoResponse(
                null, "paycoId", "홍길동", "test@example.com", "01012345678",
                true, "access-token", "refresh-token"
        );

        given(authService.processPaycoCallback(code)).willReturn(callbackResponse);
        willDoNothing().given(responseCookieUtil).addAccessTokenCookie(any(HttpServletResponse.class), eq("access-token"));
        willDoNothing().given(responseCookieUtil).addRefreshTokenCookie(any(HttpServletResponse.class), eq("refresh-token"));

        ResponseEntity<PaycoTempInfoResponse> result = authController.paycoCallback(code, response);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isEqualTo(callbackResponse);
        then(responseCookieUtil).should().addAccessTokenCookie(any(HttpServletResponse.class), eq("access-token"));
        then(responseCookieUtil).should().addRefreshTokenCookie(any(HttpServletResponse.class), eq("refresh-token"));
    }

    @Test
    void PAYCO_콜백_처리_신규_회원() {
        String code = "authorization-code";
        PaycoTempInfoResponse callbackResponse = new PaycoTempInfoResponse(
                "temp-key", "paycoId", "홍길동", "test@example.com", "01012345678",
                false, null, null
        );

        given(authService.processPaycoCallback(code)).willReturn(callbackResponse);

        ResponseEntity<PaycoTempInfoResponse> result = authController.paycoCallback(code, response);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isEqualTo(callbackResponse);
        then(responseCookieUtil).should(never()).addAccessTokenCookie(any(HttpServletResponse.class), anyString());
    }

    @Test
    void PAYCO_임시_정보_조회_성공() {
        String tempKey = "temp-key-123";
        PaycoTempInfoResponse tempInfo = new PaycoTempInfoResponse(
                tempKey, "paycoId", "홍길동", "test@example.com", "01012345678",
                false, null, null
        );

        given(authService.getPaycoTempInfo(tempKey)).willReturn(tempInfo);

        ResponseEntity<PaycoTempInfoResponse> result = authController.getPaycoTempInfo(tempKey);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isEqualTo(tempInfo);
    }

    @Test
    void PAYCO_임시_정보_삭제_성공() {
        String tempKey = "temp-key-123";

        willDoNothing().given(authService).deletePaycoTempInfo(tempKey);

        ResponseEntity<Void> result = authController.deletePaycoTempInfo(tempKey);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        then(authService).should().deletePaycoTempInfo(tempKey);
    }

    @Test
    void PAYCO_자동_로그인_성공() {
        String paycoId = "payco-id-123";
        TokenPair tokenPair = new TokenPair("access-token", "refresh-token");

        given(authService.paycoAutoLogin(paycoId)).willReturn(tokenPair);
        given(jwtTokenProvider.getMemberIdFromToken("access-token")).willReturn(1L);
        given(jwtTokenProvider.getRefreshTokenExpiration()).willReturn(604800L);
        willDoNothing().given(responseCookieUtil).addTokenCookies(any(HttpServletResponse.class), eq(tokenPair));

        ResponseEntity<LoginResponse> result = authController.paycoAutoLogin(paycoId, response);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().message()).isEqualTo("로그인 성공");
        then(responseCookieUtil).should().addTokenCookies(any(HttpServletResponse.class), eq(tokenPair));
        then(redisTemplate.opsForValue()).should().set(anyString(), eq("refresh-token"), any(Duration.class));
    }

    @Test
    void 휴면_계정_해제_성공() {
        String loginId = "testuser";
        DormantVerificationRequest request = new DormantVerificationRequest("123456");
        TokenPair tokenPair = new TokenPair("access-token", "refresh-token");

        given(authService.activateDormantMember(loginId, "123456")).willReturn(tokenPair);
        given(jwtTokenProvider.getMemberIdFromToken("access-token")).willReturn(1L);
        given(jwtTokenProvider.getRefreshTokenExpiration()).willReturn(604800L);
        willDoNothing().given(responseCookieUtil).addTokenCookies(any(HttpServletResponse.class), eq(tokenPair));

        ResponseEntity<LoginResponse> result = authController.verifyDormantMember(loginId, request, response);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().message()).isEqualTo("휴면 계정 해제 및 로그인 성공");
        then(responseCookieUtil).should().addTokenCookies(any(HttpServletResponse.class), eq(tokenPair));
        then(redisTemplate.opsForValue()).should().set(anyString(), eq("refresh-token"), any(Duration.class));
    }
}

