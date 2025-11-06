package com.nhnacademy.chaekmateauth.service;

import com.nhnacademy.chaekmateauth.dto.TokenPair;
import com.nhnacademy.chaekmateauth.dto.request.LoginRequest;
import com.nhnacademy.chaekmateauth.entity.Member;
import com.nhnacademy.chaekmateauth.exception.AuthErrorCode;
import com.nhnacademy.chaekmateauth.exception.AuthException;
import com.nhnacademy.chaekmateauth.repository.MemberRepository;
import com.nhnacademy.chaekmateauth.util.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final JwtTokenProvider jwtTokenProvider;
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    public TokenPair login(LoginRequest request) {
        Member member = memberRepository.findByLoginIdAndDeletedAtIsNull(request.loginId())
                .orElseThrow(() -> new AuthException(AuthErrorCode.MEMBER_NOT_FOUND));

        if (!passwordEncoder.matches(request.password(), member.getPassword())) {
            throw new AuthException(AuthErrorCode.INVALID_CREDENTIALS);
        }

        member.updateLastLoginAt(); // 나중에 휴면 회원 처리 시 필요, 우선 만들어놈
        memberRepository.save(member);

        return jwtTokenProvider.createTokenPair(member.getId());
    }
}
