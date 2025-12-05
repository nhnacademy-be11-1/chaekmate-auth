package com.nhnacademy.chaekmateauth.service;

import com.nhnacademy.chaekmateauth.client.DoorayClient;
import com.nhnacademy.chaekmateauth.dto.request.DoorayMessageRequest;
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
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.never;

@ActiveProfiles("test")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("NonAsciiCharacters")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class DoorayServiceTest {

    @Mock
    private DoorayClient doorayClient;

    @Mock
    private RedisTemplate<String, String> redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @InjectMocks
    private DoorayService doorayService;

    @BeforeEach
    void setUp() {
        given(redisTemplate.opsForValue()).willReturn(valueOperations);
    }

    @Test
    void 휴면_계정_인증번호_전송_성공() {
        Long memberId = 123L;
        given(doorayClient.sendMessage(any(DoorayMessageRequest.class))).willReturn(null);

        String verificationCode = doorayService.sendDormantVerificationCode(memberId);

        assertThat(verificationCode).isNotNull().hasSize(6);
        then(doorayClient).should().sendMessage(any(DoorayMessageRequest.class));
        then(valueOperations).should().set(anyString(), eq(verificationCode), any());
    }

    @Test
    void 인증번호_검증_성공() {
        Long memberId = 123L;
        String verificationCode = "123456";
        given(valueOperations.get(anyString())).willReturn(verificationCode);

        boolean result = doorayService.verifyCode(memberId, verificationCode);

        assertThat(result).isTrue();
        then(redisTemplate).should().delete(anyString());
    }

    @Test
    void 인증번호_검증_실패_불일치() {
        Long memberId = 123L;
        String storedCode = "123456";
        String inputCode = "654321";
        given(valueOperations.get(anyString())).willReturn(storedCode);

        boolean result = doorayService.verifyCode(memberId, inputCode);

        assertThat(result).isFalse();
        then(redisTemplate).should(never()).delete(anyString());
    }

    @Test
    void 인증번호_검증_실패_만료() {
        Long memberId = 123L;
        String verificationCode = "123456";
        given(valueOperations.get(anyString())).willReturn(null);

        boolean result = doorayService.verifyCode(memberId, verificationCode);

        assertThat(result).isFalse();
        then(redisTemplate).should(never()).delete(anyString());
    }

    @Test
    void 휴면_계정_인증번호_전송_실패_Dooray_전송_실패() {
        Long memberId = 123L;
        given(doorayClient.sendMessage(any(DoorayMessageRequest.class))).willThrow(new RuntimeException("Dooray 전송 실패"));

        assertThatThrownBy(() -> doorayService.sendDormantVerificationCode(memberId))
                .isInstanceOf(com.nhnacademy.chaekmateauth.exception.AuthException.class)
                .extracting("errorCode")
                .isEqualTo(com.nhnacademy.chaekmateauth.exception.AuthErrorCode.DOORAY_MESSAGE_SEND_FAILED);
    }
}
