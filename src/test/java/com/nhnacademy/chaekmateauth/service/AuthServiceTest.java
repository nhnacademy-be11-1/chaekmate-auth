package com.nhnacademy.chaekmateauth.service;

import com.nhnacademy.chaekmateauth.dto.TokenPair;
import com.nhnacademy.chaekmateauth.dto.request.LoginRequest;
import com.nhnacademy.chaekmateauth.entity.Admin;
import com.nhnacademy.chaekmateauth.entity.Member;
import com.nhnacademy.chaekmateauth.exception.AuthErrorCode;
import com.nhnacademy.chaekmateauth.exception.AuthException;
import com.nhnacademy.chaekmateauth.repository.AdminRepository;
import com.nhnacademy.chaekmateauth.repository.MemberRepository;
import com.nhnacademy.chaekmateauth.util.JwtTokenProvider;
import java.lang.reflect.Constructor;
import java.time.Duration;
import java.time.LocalDateTime;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
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
}
