package com.nhnacademy.chaekmateauth.controller;

import com.nhnacademy.chaekmateauth.common.config.CookieConfig;
import com.nhnacademy.chaekmateauth.dto.TokenPair;
import com.nhnacademy.chaekmateauth.dto.request.LoginRequest;
import com.nhnacademy.chaekmateauth.dto.response.LoginResponse;
import com.nhnacademy.chaekmateauth.dto.response.LogoutResponse;
import com.nhnacademy.chaekmateauth.dto.response.MemberInfoResponse;
import com.nhnacademy.chaekmateauth.entity.Admin;
import com.nhnacademy.chaekmateauth.entity.Member;
import com.nhnacademy.chaekmateauth.exception.AuthErrorCode;
import com.nhnacademy.chaekmateauth.exception.AuthException;
import com.nhnacademy.chaekmateauth.repository.AdminRepository;
import com.nhnacademy.chaekmateauth.repository.MemberRepository;
import com.nhnacademy.chaekmateauth.service.AuthService;
import com.nhnacademy.chaekmateauth.util.JwtTokenProvider;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;
    private final CookieConfig cookieConfig;
    private static final String REFRESH_TOKEN_PREFIX = "refresh";
    private final RedisTemplate<String, String> redisTemplate;
    private final MemberRepository memberRepository;
    private final AdminRepository adminRepository;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request,
                                               HttpServletResponse response) {
        TokenPair tokenPair = authService.login(request);

        ResponseCookie accessTokenCookie = ResponseCookie.from("accessToken", tokenPair.accessToken())
                .httpOnly(true)
                .secure(cookieConfig.isSecureCookie())
                .path("/")
                .maxAge(jwtTokenProvider.getAccessTokenExpiration())
                .sameSite("Lax")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());

        Long memberId = jwtTokenProvider.getMemberIdFromToken(tokenPair.accessToken());
        String redisKey = REFRESH_TOKEN_PREFIX + ":" + memberId;
        long refreshExpirationMillis = jwtTokenProvider.getRefreshTokenExpiration() * 1000;
        redisTemplate.opsForValue().set(redisKey, tokenPair.refreshToken(),
                Duration.ofMillis(refreshExpirationMillis));

        return ResponseEntity.ok(new LoginResponse("로그인 성공"));
    }

    @GetMapping("/me")
    public ResponseEntity<MemberInfoResponse> getMemberInfo(
            @CookieValue("accessToken") String token) {
        // 토큰 검증 및 memberId 추출
        Long id = jwtTokenProvider.getMemberIdFromToken(token);
        // userType도 추출
        String userType = jwtTokenProvider.getUserTypeFromToken(token);

        // DB에서 회원 정보 조회
        // member, admin 테이블 다 확인
        if (JwtTokenProvider.getTypeMember().equals(userType)) {
            Member member = memberRepository.findById(id)
                    .orElseThrow(() -> new AuthException(AuthErrorCode.MEMBER_NOT_FOUND));
            String role = adminRepository.existsById(id) ? "ADMIN" : "USER"; // admin테이블에 있으면 admin, 아니면 user
            return ResponseEntity.ok(new MemberInfoResponse(
                    member.getId(),
                    member.getName(),
                    role
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
    public ResponseEntity<LogoutResponse> logout(
            @CookieValue(value = "accessToken", required = false)
            String accessToken) {
        // Redis에서 RefreshToken을 삭제
        if (accessToken != null && !accessToken.trim().isEmpty()) {
            try {
                Long memberId = jwtTokenProvider.getMemberIdFromToken(accessToken);
                String redisKey = REFRESH_TOKEN_PREFIX + ":" + memberId;
                redisTemplate.delete(redisKey);
            } catch (AuthException e) {
                // 토큰이 만료되었거나 유효하지 않아도 Redis 삭제는 시도함
            }
        }

        return ResponseEntity.ok(new LogoutResponse("로그아웃 성공"));
    }
}
