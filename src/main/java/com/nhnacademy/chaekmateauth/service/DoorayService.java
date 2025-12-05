package com.nhnacademy.chaekmateauth.service;

import com.nhnacademy.chaekmateauth.client.DoorayClient;
import com.nhnacademy.chaekmateauth.dto.request.DoorayAttachment;
import com.nhnacademy.chaekmateauth.dto.request.DoorayMessageRequest;
import com.nhnacademy.chaekmateauth.exception.AuthErrorCode;
import com.nhnacademy.chaekmateauth.exception.AuthException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class DoorayService {

    private static final String DORMANT_AUTH_PREFIX = "dormant:auth:";
    private static final Duration AUTH_CODE_TTL = Duration.ofMinutes(1); // 1분동안 유효

    private final DoorayClient doorayClient;
    private final RedisTemplate<String, String> redisTemplate;

    // 인증번호 생성, 메시지 전송
    public String sendDormantVerificationCode(Long memberId) {
        // 6자리 랜덤 인증번호 생성
        String verificationCode = generateVerificationCode();

        // redis에 인증번호 저장
        String redisKey = DORMANT_AUTH_PREFIX + memberId;
        redisTemplate.opsForValue().set(redisKey, verificationCode, AUTH_CODE_TTL);

        // dooray 메시지 전송
        DoorayAttachment attachment = new DoorayAttachment(
                "휴면 계정 해제 인증번호",
                "아래의 번호를 화면에 입력해주세요\n\n" + verificationCode,
                null,
                "https://static.dooray.com/static_images/dooray-bot.png",
                "red"
        );

        DoorayMessageRequest request = new DoorayMessageRequest(
                "Chaekmate 인증",
                null,
                List.of(attachment)
        );

        try {
            doorayClient.sendMessage(request);
            log.info("휴면 계정 해제 인증번호 전송 완료: memberId={}", memberId);
        } catch (Exception e) {
            log.error("Dooray 메시지 전송 실패: memberId={}", memberId, e);
            throw new AuthException(AuthErrorCode.DOORAY_MESSAGE_SEND_FAILED, e);
        }

        return verificationCode;
    }

    // 인증번호 검증
    public boolean verifyCode(Long memberId, String verificationCode) {
        String redisKey = DORMANT_AUTH_PREFIX + memberId;
        String storedCode = redisTemplate.opsForValue().get(redisKey);

        if (storedCode == null) {
            log.warn("인증번호가 만료되었거나 존재하지 않음: memberId={}", memberId);
            return false;
        }

        boolean isValid = storedCode.equals(verificationCode);

        if (isValid) {
            // 인증 성공 시 redis에서 삭제
            redisTemplate.delete(redisKey);
            log.info("인증번호 검증 성공: memberId={}", memberId);
        } else {
            log.warn("인증번호 불일치: memberId={}", memberId);
        }

        return isValid;
    }

    // 랜덤 인증번호 생성
    private String generateVerificationCode() {
        SecureRandom random = new SecureRandom();
        // 6자리로 생성
        int code = random.nextInt(900000) + 100000; // 100000 ~ 999999
        return String.valueOf(code);
    }
}

