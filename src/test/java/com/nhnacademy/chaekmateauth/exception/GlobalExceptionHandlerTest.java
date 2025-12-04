package com.nhnacademy.chaekmateauth.exception;

import com.nhnacademy.chaekmateauth.dto.response.ErrorResponse;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("NonAsciiCharacters")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class GlobalExceptionHandlerTest {

    @InjectMocks
    private GlobalExceptionHandler globalExceptionHandler;

    @Test
    void handleAuthException_성공() {
        AuthException exception = new AuthException(AuthErrorCode.INVALID_CREDENTIALS);

        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleAuthException(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getCode()).isEqualTo("AUTH-401-3");
        assertThat(response.getBody().getMessage()).isEqualTo("아이디 또는 비밀번호가 올바르지 않습니다.");
    }

    @Test
    void handleAuthException_ACCESS_DENIED_리다이렉트() {
        AuthException exception = new AuthException(AuthErrorCode.ACCESS_DENIED);

        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleAuthException(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getCode()).isEqualTo("AUTH-403");
    }

    @Test
    void handleAuthException_MEMBER_NOT_FOUND() {
        AuthException exception = new AuthException(AuthErrorCode.MEMBER_NOT_FOUND);

        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleAuthException(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getCode()).isEqualTo("AUTH-404");
    }

    @Test
    void handleUnexpected_RuntimeException() {
        RuntimeException exception = new RuntimeException("예상치 못한 오류");

        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleUnexpected(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getCode()).isEqualTo("AUTH-500-1");
        assertThat(response.getBody().getMessage()).isEqualTo("서버 내부 오류가 발생했습니다.");
    }

    @Test
    void handleUnexpected_NullPointerException() {
        NullPointerException exception = new NullPointerException("null pointer");

        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleUnexpected(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getCode()).isEqualTo("AUTH-500-1");
    }

    @Test
    void handleUnexpected_IllegalArgumentException() {
        IllegalArgumentException exception = new IllegalArgumentException("잘못된 인자");

        ResponseEntity<ErrorResponse> response = globalExceptionHandler.handleUnexpected(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getCode()).isEqualTo("AUTH-500-1");
    }
}
