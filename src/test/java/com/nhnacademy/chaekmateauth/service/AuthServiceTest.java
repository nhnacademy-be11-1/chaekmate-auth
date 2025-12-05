package com.nhnacademy.chaekmateauth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy.chaekmateauth.common.properties.PaycoOAuthProperties;
import com.nhnacademy.chaekmateauth.dto.TokenPair;
import com.nhnacademy.chaekmateauth.dto.request.LoginRequest;
import com.nhnacademy.chaekmateauth.dto.response.PaycoMemberInfoResponse;
import com.nhnacademy.chaekmateauth.dto.response.PaycoTempInfo;
import com.nhnacademy.chaekmateauth.dto.response.PaycoTempInfoResponse;
import com.nhnacademy.chaekmateauth.dto.response.PaycoTokenResponse;
import com.nhnacademy.chaekmateauth.entity.Admin;
import com.nhnacademy.chaekmateauth.entity.Member;
import com.nhnacademy.chaekmateauth.exception.AuthErrorCode;
import com.nhnacademy.chaekmateauth.exception.AuthException;
import com.nhnacademy.chaekmateauth.repository.AdminRepository;
import com.nhnacademy.chaekmateauth.repository.MemberRepository;
import com.nhnacademy.chaekmateauth.util.JwtTokenProvider;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import org.mockito.ArgumentMatchers;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.endsWith;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;

@ActiveProfiles("test")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("NonAsciiCharacters")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class AuthServiceTest {

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private MemberRepository memberRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AdminRepository adminRepository;

    @Mock
    private RedisTemplate<String, String> redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @Mock
    private DoorayService doorayService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private PaycoOAuthProperties paycoOAuthProperties;

    @Mock
    private RestTemplate restTemplate;

    @InjectMocks
    private AuthService authService;

    private Member member;
    private Admin admin;

    @BeforeEach
    void setUp() throws Exception {
        ReflectionTestUtils.setField(authService, "activeProfile", "dev");

        // protected 생성자를 Reflection으로 호출
        Constructor<Member> memberConstructor = Member.class.getDeclaredConstructor();
        memberConstructor.setAccessible(true);
        member = memberConstructor.newInstance();
        ReflectionTestUtils.setField(member, "id", 1L);
        ReflectionTestUtils.setField(member, "loginId", "testuser");
        ReflectionTestUtils.setField(member, "password", "encodedPassword");
        ReflectionTestUtils.setField(member, "name", "테스트유저");
        ReflectionTestUtils.setField(member, "lastLoginAt", LocalDateTime.now().minusMonths(1));

        Constructor<Admin> adminConstructor = Admin.class.getDeclaredConstructor();
        adminConstructor.setAccessible(true);
        admin = adminConstructor.newInstance();
        ReflectionTestUtils.setField(admin, "id", 1L);
        ReflectionTestUtils.setField(admin, "adminLoginId", "admin");
        ReflectionTestUtils.setField(admin, "adminPassword", "encodedAdminPassword");

        given(redisTemplate.opsForValue()).willReturn(valueOperations);
    }

    @Test
    void 회원_로그인_성공() {
        LoginRequest request = new LoginRequest("testuser", "password");
        TokenPair tokenPair = new TokenPair("access-token", "refresh-token");

        given(memberRepository.findByLoginId("testuser")).willReturn(Optional.of(member));
        given(passwordEncoder.matches("password", "encodedPassword")).willReturn(true);
        given(jwtTokenProvider.createTokenPair(1L, JwtTokenProvider.getTypeMember())).willReturn(tokenPair);

        TokenPair result = authService.memberLogin(request);

        assertThat(result).isEqualTo(tokenPair);
        then(memberRepository).should().save(any(Member.class));
    }

    @Test
    void 회원_로그인_실패_잘못된_아이디() {
        LoginRequest request = new LoginRequest("wronguser", "password");

        given(memberRepository.findByLoginId("wronguser")).willReturn(Optional.empty());

        assertThatThrownBy(() -> authService.memberLogin(request))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.INVALID_CREDENTIALS);
    }

    @Test
    void 회원_로그인_실패_잘못된_비밀번호() {
        LoginRequest request = new LoginRequest("testuser", "wrongpassword");

        given(memberRepository.findByLoginId("testuser")).willReturn(Optional.of(member));
        given(passwordEncoder.matches("wrongpassword", "encodedPassword")).willReturn(false);

        assertThatThrownBy(() -> authService.memberLogin(request))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.INVALID_CREDENTIALS);
    }

    @Test
    void 회원_로그인_실패_휴면_계정() {
        LoginRequest request = new LoginRequest("testuser", "password");
        LocalDateTime fourMonthsAgo = LocalDateTime.now().minusMonths(4);
        ReflectionTestUtils.setField(member, "lastLoginAt", fourMonthsAgo);

        given(memberRepository.findByLoginId("testuser")).willReturn(Optional.of(member));
        given(passwordEncoder.matches("password", "encodedPassword")).willReturn(true);
        given(doorayService.sendDormantVerificationCode(1L)).willReturn("123456");

        assertThatThrownBy(() -> authService.memberLogin(request))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.DORMANT_MEMBER);
        then(doorayService).should().sendDormantVerificationCode(1L);
    }

    @Test
    void 관리자_로그인_성공() {
        LoginRequest request = new LoginRequest("admin", "adminpassword");
        TokenPair tokenPair = new TokenPair("admin-access-token", "admin-refresh-token");

        given(adminRepository.findByAdminLoginId("admin")).willReturn(Optional.of(admin));
        given(passwordEncoder.matches("adminpassword", "encodedAdminPassword")).willReturn(true);
        given(jwtTokenProvider.createTokenPair(1L, JwtTokenProvider.getTypeAdmin())).willReturn(tokenPair);

        TokenPair result = authService.adminLogin(request);

        assertThat(result).isEqualTo(tokenPair);
    }

    @Test
    void 관리자_로그인_실패_잘못된_아이디() {
        LoginRequest request = new LoginRequest("wrongadmin", "password");

        given(adminRepository.findByAdminLoginId("wrongadmin")).willReturn(Optional.empty());

        assertThatThrownBy(() -> authService.adminLogin(request))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.INVALID_CREDENTIALS);
    }

    @Test
    void 관리자_로그인_실패_잘못된_비밀번호() {
        LoginRequest request = new LoginRequest("admin", "wrongpassword");

        given(adminRepository.findByAdminLoginId("admin")).willReturn(Optional.of(admin));
        given(passwordEncoder.matches("wrongpassword", "encodedAdminPassword")).willReturn(false);

        assertThatThrownBy(() -> authService.adminLogin(request))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.INVALID_CREDENTIALS);
    }

    @Test
    void RefreshToken_재발급_성공() {
        String refreshToken = "valid-refresh-token";
        TokenPair newTokenPair = new TokenPair("new-access-token", "new-refresh-token");

        given(jwtTokenProvider.validateRefreshToken(refreshToken)).willReturn(true);
        given(jwtTokenProvider.getMemberIdFromToken(refreshToken)).willReturn(1L);
        given(jwtTokenProvider.getUserTypeFromToken(refreshToken)).willReturn(JwtTokenProvider.getTypeMember());
        given(valueOperations.get(anyString())).willReturn(refreshToken);
        given(jwtTokenProvider.createTokenPair(1L, JwtTokenProvider.getTypeMember())).willReturn(newTokenPair);
        given(jwtTokenProvider.getRefreshTokenExpiration()).willReturn(604800L);
        given(redisTemplate.opsForValue()).willReturn(valueOperations);
        given(redisTemplate.opsForValue().setIfPresent(anyString(), anyString(), any(Duration.class))).willReturn(true);

        TokenPair result = authService.refreshToken(refreshToken);

        assertThat(result).isEqualTo(newTokenPair);
    }

    @Test
    void RefreshToken_재발급_실패_유효하지_않은_토큰() {
        String refreshToken = "invalid-refresh-token";

        given(jwtTokenProvider.validateRefreshToken(refreshToken)).willReturn(false);

        assertThatThrownBy(() -> authService.refreshToken(refreshToken))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.REFRESH_TOKEN_INVALID);
    }

    @Test
    void RefreshToken_재발급_실패_Redis에_저장된_토큰과_불일치() {
        String refreshToken = "valid-refresh-token";
        String storedToken = "different-refresh-token";

        given(jwtTokenProvider.validateRefreshToken(refreshToken)).willReturn(true);
        given(jwtTokenProvider.getMemberIdFromToken(refreshToken)).willReturn(1L);
        given(jwtTokenProvider.getUserTypeFromToken(refreshToken)).willReturn(JwtTokenProvider.getTypeMember());
        given(valueOperations.get(anyString())).willReturn(storedToken);

        assertThatThrownBy(() -> authService.refreshToken(refreshToken))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.REFRESH_TOKEN_INVALID);
    }

    @Test
    void RefreshToken_재발급_실패_Redis에_토큰이_null() {
        String refreshToken = "valid-refresh-token";

        given(jwtTokenProvider.validateRefreshToken(refreshToken)).willReturn(true);
        given(jwtTokenProvider.getMemberIdFromToken(refreshToken)).willReturn(1L);
        given(jwtTokenProvider.getUserTypeFromToken(refreshToken)).willReturn(JwtTokenProvider.getTypeMember());
        given(valueOperations.get(anyString())).willReturn(null);

        assertThatThrownBy(() -> authService.refreshToken(refreshToken))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.REFRESH_TOKEN_INVALID);
    }

    @Test
    void 휴면_계정_해제_성공() {
        String loginId = "testuser";
        String verificationCode = "123456";
        TokenPair tokenPair = new TokenPair("access-token", "refresh-token");

        given(memberRepository.findByLoginId(loginId)).willReturn(Optional.of(member));
        given(doorayService.verifyCode(1L, verificationCode)).willReturn(true);
        given(jwtTokenProvider.createTokenPair(1L, JwtTokenProvider.getTypeMember())).willReturn(tokenPair);

        TokenPair result = authService.activateDormantMember(loginId, verificationCode);

        assertThat(result).isEqualTo(tokenPair);
        then(memberRepository).should().save(any(Member.class));
    }

    @Test
    void 휴면_계정_해제_실패_회원_없음() {
        String loginId = "wronguser";
        String verificationCode = "123456";

        given(memberRepository.findByLoginId(loginId)).willReturn(Optional.empty());

        assertThatThrownBy(() -> authService.activateDormantMember(loginId, verificationCode))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.MEMBER_NOT_FOUND);
    }

    @Test
    void 휴면_계정_해제_실패_인증번호_불일치() {
        String loginId = "testuser";
        String verificationCode = "wrongcode";

        given(memberRepository.findByLoginId(loginId)).willReturn(Optional.of(member));
        given(doorayService.verifyCode(1L, verificationCode)).willReturn(false);

        assertThatThrownBy(() -> authService.activateDormantMember(loginId, verificationCode))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.INVALID_VERIFICATION_CODE);
    }

    @Test
    void 회원_로그인_성공_lastLoginAt_null() {
        LoginRequest request = new LoginRequest("testuser", "password");
        TokenPair tokenPair = new TokenPair("access-token", "refresh-token");
        ReflectionTestUtils.setField(member, "lastLoginAt", null);

        given(memberRepository.findByLoginId("testuser")).willReturn(Optional.of(member));
        given(passwordEncoder.matches("password", "encodedPassword")).willReturn(true);
        given(jwtTokenProvider.createTokenPair(1L, JwtTokenProvider.getTypeMember())).willReturn(tokenPair);

        TokenPair result = authService.memberLogin(request);

        assertThat(result).isEqualTo(tokenPair);
        then(memberRepository).should().save(any(Member.class));
    }

    @Test
    void RefreshToken_재발급_실패_setIfPresent_실패() {
        String refreshToken = "valid-refresh-token";
        TokenPair newTokenPair = new TokenPair("new-access-token", "new-refresh-token");

        given(jwtTokenProvider.validateRefreshToken(refreshToken)).willReturn(true);
        given(jwtTokenProvider.getMemberIdFromToken(refreshToken)).willReturn(1L);
        given(jwtTokenProvider.getUserTypeFromToken(refreshToken)).willReturn(JwtTokenProvider.getTypeMember());
        given(valueOperations.get(anyString())).willReturn(refreshToken);
        given(jwtTokenProvider.createTokenPair(1L, JwtTokenProvider.getTypeMember())).willReturn(newTokenPair);
        given(jwtTokenProvider.getRefreshTokenExpiration()).willReturn(604800L);
        given(redisTemplate.opsForValue()).willReturn(valueOperations);
        given(redisTemplate.opsForValue().setIfPresent(anyString(), anyString(), any(Duration.class)))
                .willReturn(false);

        assertThatThrownBy(() -> authService.refreshToken(refreshToken))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.REFRESH_TOKEN_INVALID);
    }

    @ParameterizedTest
    @CsvSource({
            "dev, http://localhost:8080/auth/payco/callback, http%3A%2F%2Flocalhost%3A8080",
            "prod, http://localhost:8080/auth/payco/callback, https%3A%2F%2Flocalhost%3A8080",
            "prod, https://localhost:8080/auth/payco/callback, https%3A%2F%2Flocalhost%3A8080"
    })
    void PAYCO_인증_URL_생성_프로파일별_테스트(String activeProfile, String redirectUri, String expectedEncodedUri) {
        ReflectionTestUtils.setField(authService, "activeProfile", activeProfile);
        given(paycoOAuthProperties.getRedirectUri()).willReturn(redirectUri);
        given(paycoOAuthProperties.getClientId()).willReturn("test-client-id");

        String url = authService.getPaycoAuthorizationUrl();

        assertThat(url)
                .isNotNull()
                .contains("redirect_uri=" + expectedEncodedUri)
                .contains("test-client-id");
    }

    @Test
    void PAYCO_인증_URL_생성_redirectUri_null() {
        ReflectionTestUtils.setField(authService, "activeProfile", "dev");
        given(paycoOAuthProperties.getRedirectUri()).willReturn("");
        given(paycoOAuthProperties.getClientId()).willReturn("test-client-id");

        String url = authService.getPaycoAuthorizationUrl();

        assertThat(url)
                .isNotNull()
                .contains("test-client-id");
    }

    @Test
    void PAYCO_자동_로그인_성공() {
        String paycoId = "payco123";
        TokenPair tokenPair = new TokenPair("access-token", "refresh-token");

        given(memberRepository.findByLoginId(paycoId)).willReturn(Optional.of(member));
        given(jwtTokenProvider.createTokenPair(1L, JwtTokenProvider.getTypeMember())).willReturn(tokenPair);
        given(jwtTokenProvider.getRefreshTokenExpiration()).willReturn(604800L);

        TokenPair result = authService.paycoAutoLogin(paycoId);

        assertThat(result).isEqualTo(tokenPair);
        then(memberRepository).should().save(any(Member.class));
    }

    @Test
    void PAYCO_자동_로그인_실패_회원_없음() {
        String paycoId = "wrongpayco";

        given(memberRepository.findByLoginId(paycoId)).willReturn(Optional.empty());

        assertThatThrownBy(() -> authService.paycoAutoLogin(paycoId))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.MEMBER_NOT_FOUND);
    }

    @Test
    void PAYCO_임시_정보_조회_성공() throws JsonProcessingException {
        String tempKey = "temp-key-123";
        String json = "{\"paycoId\":\"payco123\",\"name\":\"테스트\",\"email\":\"test@test.com\",\"phone\":\"010-1234-5678\"}";
        PaycoTempInfo tempInfo = new PaycoTempInfo("payco123", "테스트", "test@test.com", "010-1234-5678");

        given(valueOperations.get(anyString())).willReturn(json);
        given(objectMapper.readValue(json, PaycoTempInfo.class)).willReturn(tempInfo);

        PaycoTempInfoResponse result = authService.getPaycoTempInfo(tempKey);

        assertThat(result.tempKey()).isEqualTo(tempKey);
        assertThat(result.paycoId()).isEqualTo("payco123");
        assertThat(result.name()).isEqualTo("테스트");
    }

    @Test
    void PAYCO_임시_정보_조회_실패_없음() {
        String tempKey = "wrong-key";

        given(valueOperations.get(anyString())).willReturn(null);

        assertThatThrownBy(() -> authService.getPaycoTempInfo(tempKey))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.MEMBER_NOT_FOUND);
    }

    @Test
    void PAYCO_임시_정보_조회_실패_JsonProcessingException() throws JsonProcessingException {
        String tempKey = "temp-key-123";
        String invalidJson = "invalid-json";

        given(valueOperations.get(anyString())).willReturn(invalidJson);
        given(objectMapper.readValue(invalidJson, PaycoTempInfo.class))
                .willThrow(new JsonProcessingException("JSON 파싱 실패") {});

        assertThatThrownBy(() -> authService.getPaycoTempInfo(tempKey))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.INTERNAL_SERVER_ERROR);
    }

    @Test
    void PAYCO_임시_정보_삭제_성공() {
        String tempKey = "temp-key-123";

        authService.deletePaycoTempInfo(tempKey);

        then(redisTemplate).should().delete(anyString());
    }

    @Test
    void isDormantMember_null인_경우() throws Exception {
        Method method = AuthService.class.getDeclaredMethod("isDormantMember", LocalDateTime.class);
        method.setAccessible(true);

        Boolean result = (Boolean) method.invoke(authService, (LocalDateTime) null);

        assertThat(result).isTrue();
    }

    @Test
    void isDormantMember_3개월_미만() throws Exception {
        Method method = AuthService.class.getDeclaredMethod("isDormantMember", LocalDateTime.class);
        method.setAccessible(true);
        LocalDateTime twoMonthsAgo = LocalDateTime.now().minusMonths(2);

        Boolean result = (Boolean) method.invoke(authService, twoMonthsAgo);

        assertThat(result).isFalse();
    }

    @Test
    void isDormantMember_3개월_이상() throws Exception {
        Method method = AuthService.class.getDeclaredMethod("isDormantMember", LocalDateTime.class);
        method.setAccessible(true);
        LocalDateTime fourMonthsAgo = LocalDateTime.now().minusMonths(4);

        Boolean result = (Boolean) method.invoke(authService, fourMonthsAgo);

        assertThat(result).isTrue();
    }

    @Test
    void PAYCO_콜백_처리_기존_회원_성공() throws JsonProcessingException {
        String code = "authorization-code";
        PaycoTokenResponse tokenResponse = new PaycoTokenResponse("access-token");
        PaycoMemberInfoResponse.Member paycoMember = new PaycoMemberInfoResponse.Member(
                "payco123", "홍길동", "test@example.com", "010-1234-5678");
        PaycoMemberInfoResponse.Data data = new PaycoMemberInfoResponse.Data(paycoMember);
        PaycoMemberInfoResponse.Header header = new PaycoMemberInfoResponse.Header(true, 200, "success");
        PaycoMemberInfoResponse memberInfo = new PaycoMemberInfoResponse(header, data);
        TokenPair tokenPair = new TokenPair("access-token", "refresh-token");

        given(paycoOAuthProperties.getClientId()).willReturn("test-client-id");
        given(paycoOAuthProperties.getClientSecret()).willReturn("test-secret");
        given(restTemplate.exchange(endsWith("/token"), any(), any(), eq(PaycoTokenResponse.class)))
                .willReturn(ResponseEntity.ok(tokenResponse));
        given(restTemplate.exchange(endsWith("/find_member_v2.json"), any(), any(), eq(String.class)))
                .willReturn(ResponseEntity.ok(
                        "{\"header\":{\"isSuccessful\":true,\"resultCode\":200},\"data\":{\"member\":{\"idNo\":\"payco123\",\"name\":\"홍길동\",\"email\":\"test@example.com\",\"mobile\":\"010-1234-5678\"}}}"));
        given(objectMapper.readValue(anyString(), eq(PaycoMemberInfoResponse.class))).willReturn(memberInfo);
        given(memberRepository.findByLoginId("payco123")).willReturn(Optional.of(member));
        given(jwtTokenProvider.createTokenPair(1L, JwtTokenProvider.getTypeMember())).willReturn(tokenPair);
        given(jwtTokenProvider.getRefreshTokenExpiration()).willReturn(604800L);

        PaycoTempInfoResponse result = authService.processPaycoCallback(code);

        assertThat(result.isExistingMember()).isTrue();
        assertThat(result.paycoId()).isEqualTo("payco123");
        assertThat(result.name()).isEqualTo("홍길동");
        assertThat(result.accessToken()).isEqualTo("access-token");
    }

    @Test
    void PAYCO_콜백_처리_신규_회원_성공() throws JsonProcessingException {
        String code = "authorization-code";
        PaycoTokenResponse tokenResponse = new PaycoTokenResponse("access-token");
        PaycoMemberInfoResponse.Member paycoMember = new PaycoMemberInfoResponse.Member(
                "payco456", "김철수", "kim@example.com", "010-9876-5432");
        PaycoMemberInfoResponse.Data data = new PaycoMemberInfoResponse.Data(paycoMember);
        PaycoMemberInfoResponse.Header header = new PaycoMemberInfoResponse.Header(true, 200, "success");
        PaycoMemberInfoResponse memberInfo = new PaycoMemberInfoResponse(header, data);

        given(paycoOAuthProperties.getClientId()).willReturn("test-client-id");
        given(paycoOAuthProperties.getClientSecret()).willReturn("test-secret");
        given(restTemplate.exchange(endsWith("/token"), any(), any(), eq(PaycoTokenResponse.class)))
                .willReturn(ResponseEntity.ok(tokenResponse));
        given(restTemplate.exchange(endsWith("/find_member_v2.json"), any(), any(), eq(String.class)))
                .willReturn(ResponseEntity.ok(
                        "{\"header\":{\"isSuccessful\":true,\"resultCode\":200},\"data\":{\"member\":{\"idNo\":\"payco456\",\"name\":\"김철수\",\"email\":\"kim@example.com\",\"mobile\":\"010-9876-5432\"}}}"));
        given(objectMapper.readValue(anyString(), eq(PaycoMemberInfoResponse.class))).willReturn(memberInfo);
        given(memberRepository.findByLoginId("payco456")).willReturn(Optional.empty());
        given(objectMapper.writeValueAsString(any())).willReturn("{\"paycoId\":\"payco456\"}");

        PaycoTempInfoResponse result = authService.processPaycoCallback(code);

        assertThat(result.isExistingMember()).isFalse();
        assertThat(result.paycoId()).isEqualTo("payco456");
        assertThat(result.name()).isEqualTo("김철수");
        assertThat(result.tempKey()).isNotNull();
        assertThat(result.accessToken()).isNull();
    }

    @Test
    void PAYCO_콜백_처리_실패_memberInfo_data_null() throws JsonProcessingException {
        String code = "authorization-code";
        PaycoTokenResponse tokenResponse = new PaycoTokenResponse("access-token");
        PaycoMemberInfoResponse.Header header = new PaycoMemberInfoResponse.Header(true, 200, "success");
        PaycoMemberInfoResponse memberInfo = new PaycoMemberInfoResponse(header, null);

        given(paycoOAuthProperties.getClientId()).willReturn("test-client-id");
        given(paycoOAuthProperties.getClientSecret()).willReturn("test-secret");
        given(restTemplate.exchange(endsWith("/token"), any(), any(), eq(PaycoTokenResponse.class)))
                .willReturn(ResponseEntity.ok(tokenResponse));
        given(restTemplate.exchange(endsWith("/find_member_v2.json"), any(), any(), eq(String.class)))
                .willReturn(ResponseEntity.ok("{\"header\":{\"isSuccessful\":true,\"resultCode\":200},\"data\":null}"));
        given(objectMapper.readValue(anyString(), eq(PaycoMemberInfoResponse.class))).willReturn(memberInfo);

        assertThatThrownBy(() -> authService.processPaycoCallback(code))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.MEMBER_NOT_FOUND);
    }

    @Test
    void PAYCO_콜백_처리_실패_name_null_또는_빈문자열() throws JsonProcessingException {
        String code = "authorization-code";
        PaycoTokenResponse tokenResponse = new PaycoTokenResponse("access-token");
        PaycoMemberInfoResponse.Member paycoMember = new PaycoMemberInfoResponse.Member(
                "payco789", null, "test@example.com", "010-1111-2222");
        PaycoMemberInfoResponse.Data data = new PaycoMemberInfoResponse.Data(paycoMember);
        PaycoMemberInfoResponse.Header header = new PaycoMemberInfoResponse.Header(true, 200, "success");
        PaycoMemberInfoResponse memberInfo = new PaycoMemberInfoResponse(header, data);
        TokenPair tokenPair = new TokenPair("access-token", "refresh-token");

        given(paycoOAuthProperties.getClientId()).willReturn("test-client-id");
        given(paycoOAuthProperties.getClientSecret()).willReturn("test-secret");
        given(restTemplate.exchange(endsWith("/token"), any(), any(), eq(PaycoTokenResponse.class)))
                .willReturn(ResponseEntity.ok(tokenResponse));
        given(restTemplate.exchange(endsWith("/find_member_v2.json"), any(), any(), eq(String.class)))
                .willReturn(ResponseEntity.ok(
                        "{\"header\":{\"isSuccessful\":true,\"resultCode\":200},\"data\":{\"member\":{\"idNo\":\"payco789\",\"name\":null,\"email\":\"test@example.com\",\"mobile\":\"010-1111-2222\"}}}"));
        given(objectMapper.readValue(anyString(), eq(PaycoMemberInfoResponse.class))).willReturn(memberInfo);
        given(memberRepository.findByLoginId("payco789")).willReturn(Optional.of(member));
        given(jwtTokenProvider.createTokenPair(1L, JwtTokenProvider.getTypeMember())).willReturn(tokenPair);
        given(jwtTokenProvider.getRefreshTokenExpiration()).willReturn(604800L);

        PaycoTempInfoResponse result = authService.processPaycoCallback(code);

        assertThat(result.name()).isNull();
    }

    @Test
    void PAYCO_토큰_교환_실패_응답_실패() {
        String code = "invalid-code";

        given(paycoOAuthProperties.getClientId()).willReturn("test-client-id");
        given(paycoOAuthProperties.getClientSecret()).willReturn("test-secret");
        given(restTemplate.exchange(anyString(), any(), any(), ArgumentMatchers.<Class<?>>any()))
                .willReturn(ResponseEntity.status(HttpStatus.BAD_REQUEST).build());

        assertThatThrownBy(() -> {
            // processPaycoCallback을 통해 간접적으로 테스트
            Method method = AuthService.class.getDeclaredMethod("exchangePaycoToken", String.class);
            method.setAccessible(true);
            method.invoke(authService, code);
        })
                .hasCauseInstanceOf(AuthException.class);
    }

    @Test
    void PAYCO_토큰_교환_실패_예외_발생() {
        String code = "invalid-code";

        given(paycoOAuthProperties.getClientId()).willReturn("test-client-id");
        given(paycoOAuthProperties.getClientSecret()).willReturn("test-secret");
        given(restTemplate.exchange(anyString(), any(), any(), ArgumentMatchers.<Class<?>>any()))
                .willThrow(new RestClientException("Network error"));

        assertThatThrownBy(() -> {
            Method method = AuthService.class.getDeclaredMethod("exchangePaycoToken", String.class);
            method.setAccessible(true);
            method.invoke(authService, code);
        })
                .hasCauseInstanceOf(AuthException.class);
    }

    @Test
    void PAYCO_회원_정보_조회_실패_응답_실패() {
        String accessToken = "access-token";

        given(paycoOAuthProperties.getClientId()).willReturn("test-client-id");
        given(restTemplate.exchange(anyString(), any(), any(), ArgumentMatchers.<Class<?>>any()))
                .willReturn(ResponseEntity.status(HttpStatus.BAD_REQUEST).build());

        assertThatThrownBy(() -> {
            Method method = AuthService.class.getDeclaredMethod("getPaycoMemberInfo", String.class);
            method.setAccessible(true);
            method.invoke(authService, accessToken);
        })
                .hasCauseInstanceOf(AuthException.class);
    }

    @Test
    void PAYCO_회원_정보_조회_실패_예외_발생() {
        String accessToken = "access-token";

        given(paycoOAuthProperties.getClientId()).willReturn("test-client-id");
        given(restTemplate.exchange(anyString(), any(), any(), ArgumentMatchers.<Class<?>>any()))
                .willThrow(new RestClientException("Network error"));

        assertThatThrownBy(() -> {
            Method method = AuthService.class.getDeclaredMethod("getPaycoMemberInfo", String.class);
            method.setAccessible(true);
            method.invoke(authService, accessToken);
        })
                .hasCauseInstanceOf(AuthException.class);
    }

    @Test
    void PAYCO_콜백_처리_실패_JsonProcessingException_임시정보_저장() throws JsonProcessingException {
        String code = "authorization-code";
        PaycoTokenResponse tokenResponse = new PaycoTokenResponse("access-token");
        PaycoMemberInfoResponse.Member paycoMember = new PaycoMemberInfoResponse.Member(
                "payco999", "테스트", "test@example.com", "010-9999-9999");
        PaycoMemberInfoResponse.Data data = new PaycoMemberInfoResponse.Data(paycoMember);
        PaycoMemberInfoResponse.Header header = new PaycoMemberInfoResponse.Header(true, 200, "success");
        PaycoMemberInfoResponse memberInfo = new PaycoMemberInfoResponse(header, data);

        given(paycoOAuthProperties.getClientId()).willReturn("test-client-id");
        given(paycoOAuthProperties.getClientSecret()).willReturn("test-secret");
        given(restTemplate.exchange(endsWith("/token"), any(), any(), eq(PaycoTokenResponse.class)))
                .willReturn(ResponseEntity.ok(tokenResponse));
        given(restTemplate.exchange(endsWith("/find_member_v2.json"), any(), any(), eq(String.class)))
                .willReturn(ResponseEntity.ok("{\"header\":{\"isSuccessful\":true}}"));
        given(objectMapper.readValue(anyString(), eq(PaycoMemberInfoResponse.class))).willReturn(memberInfo);
        given(memberRepository.findByLoginId("payco999")).willReturn(Optional.empty());
        given(objectMapper.writeValueAsString(any())).willThrow(new JsonProcessingException("JSON 변환 실패") {
        });

        assertThatThrownBy(() -> authService.processPaycoCallback(code))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.INTERNAL_SERVER_ERROR);
    }
}
