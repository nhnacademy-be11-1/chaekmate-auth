package com.nhnacademy.chaekmateauth.aop;

import com.nhnacademy.chaekmateauth.common.properties.JwtProperties;
import com.nhnacademy.chaekmateauth.exception.AuthErrorCode;
import com.nhnacademy.chaekmateauth.exception.AuthException;
import com.nhnacademy.chaekmateauth.util.JwtTokenProvider;
import jakarta.servlet.http.Cookie;
import org.aspectj.lang.ProceedingJoinPoint;
import org.junit.jupiter.api.AfterEach;
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
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ActiveProfiles("test")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("NonAsciiCharacters")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class RoleCheckAspectTest {

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private ProceedingJoinPoint joinPoint;

    @InjectMocks
    private RoleCheckAspect roleCheckAspect;

    @BeforeEach
    void setUp() throws Throwable {
        when(joinPoint.proceed()).thenReturn("success");
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void RequireMember_어노테이션_토큰_없을_때_예외_발생() throws Throwable {
        RequestContextHolder.setRequestAttributes(null);

        AuthException exception = assertThrows(AuthException.class, () -> roleCheckAspect.checkMember(joinPoint));

        assertThat(exception.getErrorCode()).isEqualTo(AuthErrorCode.TOKEN_INVALID);
        verify(joinPoint, never()).proceed();
    }

    @Test
    void RequireMember_어노테이션_Member_토큰_있을_때_통과() throws Throwable {
        String validToken = "valid-member-token";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("accessToken", validToken));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        when(jwtTokenProvider.getMemberIdFromToken(validToken)).thenReturn(1L);
        when(jwtTokenProvider.getUserTypeFromToken(validToken)).thenReturn(JwtTokenProvider.getTypeMember());

        Object result = roleCheckAspect.checkMember(joinPoint);

        assertThat(result).isEqualTo("success");
        verify(joinPoint).proceed();
        verify(jwtTokenProvider).getMemberIdFromToken(validToken);
        verify(jwtTokenProvider).getUserTypeFromToken(validToken);
    }

    @Test
    void RequireMember_어노테이션_Admin_토큰_있을_때_통과() throws Throwable {
        String validToken = "valid-admin-token";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("accessToken", validToken));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        when(jwtTokenProvider.getMemberIdFromToken(validToken)).thenReturn(1L);
        when(jwtTokenProvider.getUserTypeFromToken(validToken)).thenReturn(JwtTokenProvider.getTypeAdmin());

        Object result = roleCheckAspect.checkMember(joinPoint);

        assertThat(result).isEqualTo("success");
        verify(joinPoint).proceed();
    }

    @Test
    void RequireAdmin_어노테이션_Admin_토큰_있을_때_통과() throws Throwable {
        String validToken = "valid-admin-token";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("accessToken", validToken));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        when(jwtTokenProvider.getMemberIdFromToken(validToken)).thenReturn(1L);
        when(jwtTokenProvider.getUserTypeFromToken(validToken)).thenReturn(JwtTokenProvider.getTypeAdmin());

        Object result = roleCheckAspect.checkAdmin(joinPoint);

        assertThat(result).isEqualTo("success");
        verify(joinPoint).proceed();
    }

    @Test
    void RequireAdmin_어노테이션_Member_토큰일_때_예외_발생() throws Throwable {
        String memberToken = "member-token";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("accessToken", memberToken));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        when(jwtTokenProvider.getMemberIdFromToken(memberToken)).thenReturn(1L);
        when(jwtTokenProvider.getUserTypeFromToken(memberToken)).thenReturn(JwtTokenProvider.getTypeMember());

        AuthException exception = assertThrows(AuthException.class, () -> roleCheckAspect.checkAdmin(joinPoint));

        assertThat(exception.getErrorCode()).isEqualTo(AuthErrorCode.TOKEN_INVALID);
        verify(joinPoint, never()).proceed();
    }

    @Test
    void RequireAdmin_어노테이션_토큰_없을_때_예외_발생() throws Throwable {
        RequestContextHolder.setRequestAttributes(null);

        AuthException exception = assertThrows(AuthException.class, () -> roleCheckAspect.checkAdmin(joinPoint));

        assertThat(exception.getErrorCode()).isEqualTo(AuthErrorCode.TOKEN_INVALID);
        verify(joinPoint, never()).proceed();
    }
}
