package com.nhnacademy.chaekmateauth.exception;

import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings("NonAsciiCharacters")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class AuthExceptionTest {

    @Test
    void AuthException_생성_BaseErrorCode만_사용() {
        AuthException exception = new AuthException(AuthErrorCode.INVALID_CREDENTIALS);

        assertThat(exception.getErrorCode()).isEqualTo(AuthErrorCode.INVALID_CREDENTIALS);
        assertThat(exception.getMessage()).isEqualTo(AuthErrorCode.INVALID_CREDENTIALS.getMessage());
    }

    @Test
    void AuthException_생성_BaseErrorCode와_Throwable_사용() {
        RuntimeException cause = new RuntimeException("원인 예외");
        AuthException exception = new AuthException(AuthErrorCode.INTERNAL_SERVER_ERROR, cause);

        assertThat(exception.getErrorCode()).isEqualTo(AuthErrorCode.INTERNAL_SERVER_ERROR);
        assertThat(exception.getMessage()).isEqualTo(AuthErrorCode.INTERNAL_SERVER_ERROR.getMessage());
        assertThat(exception.getCause()).isEqualTo(cause);
    }
}

