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
import java.time.Duration;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private static final String REFRESH_TOKEN_PREFIX = "refresh";

    private final JwtTokenProvider jwtTokenProvider;
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final AdminRepository adminRepository;
    private final RedisTemplate<String, String> redisTemplate;


    public TokenPair memberLogin(LoginRequest request) {
        Optional<Member> memberOpt = memberRepository.findByLoginId(request.loginId());
        if (memberOpt.isPresent()) {
            Member member = memberOpt.get();
            if (passwordEncoder.matches(request.password(), member.getPassword())) {
                member.updateLastLoginAt();
                memberRepository.save(member);
                return jwtTokenProvider.createTokenPair(member.getId(), JwtTokenProvider.getTypeMember());
            }
        }
        throw new AuthException(AuthErrorCode.INVALID_CREDENTIALS);
    }

        // 3개월 지나서 휴면해제 인증 필요
        //if(){
            // dooray message sender로 메시지 보내기
        //}
    public TokenPair adminLogin(LoginRequest request) {
        Optional<Admin> adminOpt = adminRepository.findByAdminLoginId(request.loginId());
        if (adminOpt.isPresent()) {
            Admin admin = adminOpt.get();
            if (passwordEncoder.matches(request.password(), admin.getAdminPassword())) {
                return jwtTokenProvider.createTokenPair(admin.getId(), JwtTokenProvider.getTypeAdmin());
            }
        }

        throw new AuthException(AuthErrorCode.INVALID_CREDENTIALS);
    }

    // refreshToken메서드
    public TokenPair refreshToken(String refreshToken) {
        // refreshToken검증
        if (!jwtTokenProvider.validateRefreshToken(refreshToken)) {
            throw new AuthException(AuthErrorCode.REFRESH_TOKEN_INVALID);
        }

        Long memberId = jwtTokenProvider.getMemberIdFromToken(refreshToken);
        String userType = jwtTokenProvider.getUserTypeFromToken(refreshToken);

        // Redis에서도 refreshToken 검증
        String redisKey = REFRESH_TOKEN_PREFIX + ":" + memberId;
        String storedRefreshToken = redisTemplate.opsForValue().get(redisKey);

        if (storedRefreshToken == null || !storedRefreshToken.equals(refreshToken)) {
            throw new AuthException(AuthErrorCode.REFRESH_TOKEN_INVALID);
        }

        // 새로운 토큰 생성
        TokenPair newTokenPair = jwtTokenProvider.createTokenPair(memberId, userType);

        // Redis 업데이트 (기존 삭제, 새로 저장)
        long refreshExpirationMillis = jwtTokenProvider.getRefreshTokenExpiration() * 1000;
        Boolean success = redisTemplate.opsForValue().setIfPresent(
                redisKey,
                newTokenPair.refreshToken(),
                Duration.ofMillis(refreshExpirationMillis)
        );

        if (!Boolean.TRUE.equals(success)) {
            // 다른 요청이 먼저 토큰을 변경했거나 토큰이 이미 삭제됨
            throw new AuthException(AuthErrorCode.REFRESH_TOKEN_INVALID);
        }

        return newTokenPair;
    }
}
