package com.nhnacademy.chaekmateauth.controller;

import com.nhnacademy.chaekmateauth.common.config.CookieConfig;
import com.nhnacademy.chaekmateauth.dto.TokenPair;
import com.nhnacademy.chaekmateauth.dto.request.LoginRequest;
import com.nhnacademy.chaekmateauth.dto.response.LoginResponse;
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
}
