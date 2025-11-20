package com.nhnacademy.chaekmateauth.dto.response;

// PAYCO 임시 정보 응답 DTO
// 회원가입 페이지로 전달할 PAYCO 정보 또는 기존 회원 로그인 정보
public record PaycoTempInfoResponse(
        String tempKey,      // 임시 저장 키 (회원가입 완료 후 조회/삭제용, 기존 회원이면 null)
        String paycoId,      // PAYCO ID
        String name,         // 이름
        String email,        // 이메일 (있을 경우)
        String phone,        // 전화번호 (있을 경우)
        Boolean isExistingMember,  // 기존 회원 여부
        String accessToken,  // 기존 회원이면 accessToken, 신규 회원이면 null
        String refreshToken  // 기존 회원이면 refreshToken, 신규 회원이면 null
) {
}