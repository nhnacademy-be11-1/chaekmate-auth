package com.nhnacademy.chaekmateauth.dto.response;

public record MemberInfoResponse(
        Long memberId,
        String name,
        String role
) {
}
