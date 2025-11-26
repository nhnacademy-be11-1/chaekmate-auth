package com.nhnacademy.chaekmateauth.controller;

import com.nhnacademy.chaekmateauth.dto.TokenPair;
import com.nhnacademy.chaekmateauth.dto.request.DormantVerificationRequest;
import com.nhnacademy.chaekmateauth.dto.request.LoginRequest;
import com.nhnacademy.chaekmateauth.dto.response.LoginResponse;
import com.nhnacademy.chaekmateauth.dto.response.LogoutResponse;
import com.nhnacademy.chaekmateauth.annotation.RequireMember;
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
import jakarta.validation.Valid;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;
    private final ResponseCookieUtil responseCookieUtil;
    private static final String REFRESH_TOKEN_PREFIX = "refresh";
    private final RedisTemplate<String, String> redisTemplate;
    private final MemberRepository memberRepository;
    private final AdminRepository adminRepository;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> memberLogin(@Valid @RequestBody LoginRequest request,
                                               HttpServletResponse response) {
        TokenPair tokenPair = authService.memberLogin(request);

        responseCookieUtil.addTokenCookies(response, tokenPair);
        log.info("일반 로그인 - 토큰 쿠키 설정 완료");

        Long memberId = jwtTokenProvider.getMemberIdFromToken(tokenPair.accessToken());
        String redisKey = REFRESH_TOKEN_PREFIX + ":" + memberId;
        long refreshExpirationMillis = jwtTokenProvider.getRefreshTokenExpiration() * 1000;
        redisTemplate.opsForValue().set(redisKey, tokenPair.refreshToken(),
                Duration.ofMillis(refreshExpirationMillis));

        return ResponseEntity.ok(new LoginResponse("로그인 성공"));
    }

    @PostMapping("/admin/login")
    public ResponseEntity<LoginResponse> adminLogin(@Valid @RequestBody LoginRequest request,
                                                    HttpServletResponse response) {
        TokenPair tokenPair = authService.adminLogin(request);

        responseCookieUtil.addTokenCookies(response, tokenPair);

        Long adminId = jwtTokenProvider.getMemberIdFromToken(tokenPair.accessToken());
        String redisKey = REFRESH_TOKEN_PREFIX + ":" + adminId;
        long refreshExpirationMillis = jwtTokenProvider.getRefreshTokenExpiration() * 1000;
        redisTemplate.opsForValue().set(redisKey, tokenPair.refreshToken(),
                Duration.ofMillis(refreshExpirationMillis));

        return ResponseEntity.ok(new LoginResponse("관리자 로그인 성공"));
    }

    @GetMapping("/me")
    @RequireMember
    public ResponseEntity<MemberInfoResponse> getMemberInfo(
            @CookieValue(ResponseCookieUtil.ACCESS_TOKEN_COOKIE_NAME) String token) {
        // 토큰 검증 및 memberId 추출
        Long id = jwtTokenProvider.getMemberIdFromToken(token);
        // userType도 추출
        String userType = jwtTokenProvider.getUserTypeFromToken(token);

        // DB에서 회원 정보 조회
        if (JwtTokenProvider.getTypeMember().equals(userType)) {
            Member member = memberRepository.findById(id)
                    .orElseThrow(() -> new AuthException(AuthErrorCode.MEMBER_NOT_FOUND));
            return ResponseEntity.ok(new MemberInfoResponse(
                    member.getId(),
                    member.getName(),
                    "USER"
            ));
        }
        else if (JwtTokenProvider.getTypeAdmin().equals(userType)) {
            Admin admin = adminRepository.findById(id)
                    .orElseThrow(() -> new AuthException(AuthErrorCode.MEMBER_NOT_FOUND));
            return ResponseEntity.ok(new MemberInfoResponse(
                    admin.getId(),
                    "admin",
                    "ADMIN"
            ));
        }

        throw new AuthException(AuthErrorCode.MEMBER_NOT_FOUND);
    }

    @PostMapping("/logout")
    @RequireMember
    public ResponseEntity<LogoutResponse> logout(
            @CookieValue(value = ResponseCookieUtil.ACCESS_TOKEN_COOKIE_NAME, required = false)
            String accessToken,
            @CookieValue(value = ResponseCookieUtil.REFRESH_TOKEN_COOKIE_NAME, required = false)
            String refreshToken) {

        // Redis에서 RefreshToken을 삭제
        Long memberId = null;
        if (accessToken != null && !accessToken.trim().isEmpty()) {
            try {
                memberId = jwtTokenProvider.getMemberIdFromToken(accessToken);
            } catch (AuthException e) {
                // AccessToken이 만료 혹은 유효하지 않은 거임
            }
        }

        // accessToken에서 추출 실패 했으니 refreskToken에서 시도
        if (memberId == null && refreshToken != null && !refreshToken.trim().isEmpty()) {
            try {
                memberId = jwtTokenProvider.getMemberIdFromToken(refreshToken);
            } catch (AuthException e) {
                // RefreshToken도 만료되었거나 유효하지 않음
            }
        }

        // memberId 추출했다면 redis에서 refreskToken삭제
        if(memberId != null) {
            String redisKey = REFRESH_TOKEN_PREFIX + ":" + memberId;
            redisTemplate.delete(redisKey);
        }
        return ResponseEntity.ok(new LogoutResponse("로그아웃 성공"));
    }

    // refreshToken을 쿠키에 저장?
    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refreshToken(
            @CookieValue(ResponseCookieUtil.REFRESH_TOKEN_COOKIE_NAME) String refreshToken,
            HttpServletResponse response) {
        // refreshToken 발급
        TokenPair tokenPair = authService.refreshToken(refreshToken);

        // 새 토큰 쿠키 설정
        responseCookieUtil.addTokenCookies(response, tokenPair);

        return ResponseEntity.ok(new LoginResponse("토큰 재발급 성공"));
    }

    /**
     * PAYCO 인증 URL 반환
     */
    @GetMapping("/payco/authorize")
    public ResponseEntity<PaycoAuthorizationResponse> getPaycoAuthorizationUrl() {
        String authorizationUrl = authService.getPaycoAuthorizationUrl();
        return ResponseEntity.ok(new PaycoAuthorizationResponse(authorizationUrl));
    }

    /**
     * PAYCO OAuth 콜백 처리
     * 기존 회원이면 바로 로그인, 없으면 회원가입 페이지로 리다이렉트
     */
    @GetMapping("/payco/callback")
    public ResponseEntity<PaycoTempInfoResponse> paycoCallback(
            @RequestParam("code") String code,
            HttpServletResponse response) {

        PaycoTempInfoResponse callbackResponse = authService.processPaycoCallback(code);

        // 기존 회원이면 쿠키 설정
        if (Boolean.TRUE.equals(callbackResponse.isExistingMember()) && callbackResponse.accessToken() != null) {
            responseCookieUtil.addAccessTokenCookie(response, callbackResponse.accessToken());
            responseCookieUtil.addRefreshTokenCookie(response, callbackResponse.refreshToken());
        }

        return ResponseEntity.ok(callbackResponse);
    }

    /**
     * PAYCO 임시 정보 조회
     */
    @GetMapping("/payco/temp/{tempKey}")
    public ResponseEntity<PaycoTempInfoResponse> getPaycoTempInfo(@PathVariable String tempKey) {
        PaycoTempInfoResponse tempInfo = authService.getPaycoTempInfo(tempKey);

        return ResponseEntity.ok(tempInfo);
    }

    /**
     * PAYCO 임시 정보 삭제 (회원가입 완료 후)
     */
    @DeleteMapping("/payco/temp/{tempKey}")
    public ResponseEntity<Void> deletePaycoTempInfo(@PathVariable String tempKey) {
        authService.deletePaycoTempInfo(tempKey);
        return ResponseEntity.ok().build();
    }

    /**
     * PAYCO 회원가입 후 자동 로그인
     */
    @PostMapping("/payco/login")
    public ResponseEntity<LoginResponse> paycoAutoLogin(@RequestParam("paycoId") String paycoId,
                                                        HttpServletResponse response) {
        TokenPair tokenPair = authService.paycoAutoLogin(paycoId);

        responseCookieUtil.addTokenCookies(response, tokenPair);
        log.info("PAYCO 자동 로그인 - 토큰 쿠키 설정 완료");

        Long memberId = jwtTokenProvider.getMemberIdFromToken(tokenPair.accessToken());
        String redisKey = REFRESH_TOKEN_PREFIX + ":" + memberId;
        long refreshExpirationMillis = jwtTokenProvider.getRefreshTokenExpiration() * 1000;
        redisTemplate.opsForValue().set(redisKey, tokenPair.refreshToken(),
                Duration.ofMillis(refreshExpirationMillis));

        return ResponseEntity.ok(new LoginResponse("로그인 성공"));
    }

    @PostMapping("/dormant/verify")
    public ResponseEntity<LoginResponse> verifyDormantMember(
            @RequestParam("loginId") String loginId,
            @Valid @RequestBody DormantVerificationRequest request,
            HttpServletResponse response) {

        TokenPair tokenPair = authService.activateDormantMember(loginId, request.verificationCode());

        // 쿠키 설정
        responseCookieUtil.addTokenCookies(response, tokenPair);

        // Redis에 refreshToken 저장
        Long memberId = jwtTokenProvider.getMemberIdFromToken(tokenPair.accessToken());
        String redisKey = REFRESH_TOKEN_PREFIX + ":" + memberId;
        long refreshExpirationMillis = jwtTokenProvider.getRefreshTokenExpiration() * 1000;
        redisTemplate.opsForValue().set(redisKey, tokenPair.refreshToken(),
                Duration.ofMillis(refreshExpirationMillis));

        return ResponseEntity.ok(new LoginResponse("휴면 계정 해제 및 로그인 성공"));
    }
}
