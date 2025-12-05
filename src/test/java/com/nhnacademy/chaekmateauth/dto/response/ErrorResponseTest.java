package com.nhnacademy.chaekmateauth.dto.response;

import com.nhnacademy.chaekmateauth.exception.AuthErrorCode;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings("NonAsciiCharacters")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class ErrorResponseTest {

    @Test
    void from_메서드_성공() {
        ErrorResponse response = ErrorResponse.from(AuthErrorCode.INVALID_CREDENTIALS);

        assertThat(response.getCode()).isEqualTo(AuthErrorCode.INVALID_CREDENTIALS.getCode());
        assertThat(response.getMessage()).isEqualTo(AuthErrorCode.INVALID_CREDENTIALS.getMessage());
    }

    @Test
    void 생성자_테스트() {
        ErrorResponse response = new ErrorResponse("TEST_CODE", "테스트 메시지");

        assertThat(response.getCode()).isEqualTo("TEST_CODE");
        assertThat(response.getMessage()).isEqualTo("테스트 메시지");
    }
}

