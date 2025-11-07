package com.nhnacademy.chaekmateauth.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum AuthErrorCode implements BaseErrorCode {

    // 401
    TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "AUTH-401", "토큰이 만료되었습니다."),
    TOKEN_INVALID(HttpStatus.UNAUTHORIZED, "AUTH-401", "유효하지 않은 토큰입니다."),

    // 500
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "AUTH-500", "서버 내부 오류가 발생했습니다."),
    TOKEN_PARSE_FAILED(HttpStatus.INTERNAL_SERVER_ERROR, "AUTH-500", "토큰 파싱에 실패했습니다.");

    private final HttpStatus status;
    private final String code;
    private final String message;
}
