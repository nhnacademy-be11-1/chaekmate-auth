package com.nhnacademy.chaekmateauth.dto.response;

import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings("NonAsciiCharacters")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class PaycoTokenResponseTest {

    @Test
    void PaycoTokenResponse_생성_성공() {
        PaycoTokenResponse response = new PaycoTokenResponse("test-access-token");

        assertThat(response.accessToken()).isEqualTo("test-access-token");
    }
}
