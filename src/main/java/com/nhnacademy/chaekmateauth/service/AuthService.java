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
import java.util.Optional;
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
    private final AdminRepository adminRepository;

    public TokenPair login(LoginRequest request) {
        Optional<Member> memberOpt = memberRepository.findByLoginId(request.loginId());
        if (memberOpt.isPresent()) {
            Member member = memberOpt.get();
            if (passwordEncoder.matches(request.password(), member.getPassword())) {
                member.updateLastLoginAt();
                memberRepository.save(member);
                return jwtTokenProvider.createTokenPair(member.getId(), JwtTokenProvider.getTypeMember());
            }
        }

        // 3개월 지나서 휴면해제 인증 필요
        //if(){
            // dooray message sender로 메시지 보내기
        //}
        Optional<Admin> adminOpt = adminRepository.findByAdminLoginId(request.loginId());
        if (adminOpt.isPresent()) {
            Admin admin = adminOpt.get();
            if (passwordEncoder.matches(request.password(), admin.getAdminPassword())) {
                return jwtTokenProvider.createTokenPair(admin.getId(), JwtTokenProvider.getTypeAdmin());
            }
        }

        throw new AuthException(AuthErrorCode.INVALID_CREDENTIALS);
    }
}
