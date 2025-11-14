package com.nhnacademy.chaekmateauth.aop;

import com.nhnacademy.chaekmateauth.exception.AuthErrorCode;
import com.nhnacademy.chaekmateauth.exception.AuthException;
import com.nhnacademy.chaekmateauth.repository.AdminRepository;
import com.nhnacademy.chaekmateauth.util.CookieUtil;
import com.nhnacademy.chaekmateauth.util.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class RoleCheckAspect {

    private final JwtTokenProvider jwtTokenProvider;

    @Around("@annotation(com.nhnacademy.chaekmateauth.annotation.RequireMember)")
    public Object checkMember(ProceedingJoinPoint joinPoint) throws Throwable{
        String accessToken = CookieUtil.extractAccessTokenFromCookie();
        if(accessToken == null) {
            throw new AuthException(AuthErrorCode.TOKEN_INVALID);
        }

        Long memberId = jwtTokenProvider.getMemberIdFromToken(accessToken);
        String userType = jwtTokenProvider.getUserTypeFromToken(accessToken);

        // user거나 admin이면 통과
        if (JwtTokenProvider.getTypeMember().equals(userType) || JwtTokenProvider.getTypeAdmin().equals(userType)) {
            log.debug("회원 권한 체크 통과: memberId={}, userType={}", memberId, userType);
            return joinPoint.proceed();
        }

        throw new AuthException(AuthErrorCode.TOKEN_INVALID);
    }

    @Around("@annotation(com.nhnacademy.chaekmateauth.annotation.RequireAdmin)")
    public Object checkAdmin(ProceedingJoinPoint joinPoint) throws Throwable{
        String accessToken = CookieUtil.extractAccessTokenFromCookie();
        if(accessToken == null) {
            throw new AuthException(AuthErrorCode.TOKEN_INVALID);
        }

        Long memberId = jwtTokenProvider.getMemberIdFromToken(accessToken);
        String userType = jwtTokenProvider.getUserTypeFromToken(accessToken);

        // admin권한 체크
        if (JwtTokenProvider.getTypeAdmin().equals(userType)) {
            log.debug("관리자 권한 체크 통과: memberId={}", memberId);
            return joinPoint.proceed();
        }

        throw new AuthException(AuthErrorCode.TOKEN_INVALID);
    }
}
