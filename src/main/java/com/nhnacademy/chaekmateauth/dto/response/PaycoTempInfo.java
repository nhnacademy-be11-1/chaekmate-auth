package com.nhnacademy.chaekmateauth.dto.response;

// Payco 임시 정보 (redis에 저장용, tempKey 제외)
public record PaycoTempInfo(
        String paycoId,      // PAYCO ID
        String name,         // 이름
        String email,        // 이메일 (있을 경우)
        String phone         // 전화번호 (있을 경우)
) {
}