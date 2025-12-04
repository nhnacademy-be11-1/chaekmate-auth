package com.nhnacademy.chaekmateauth.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum AuthErrorCode implements BaseErrorCode {

    // 401
    TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "AUTH-401-1", "토큰이 만료되었습니다."),
    TOKEN_INVALID(HttpStatus.UNAUTHORIZED, "AUTH-401-2", "유효하지 않은 토큰입니다."),
    INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED, "AUTH-401-3", "아이디 또는 비밀번호가 올바르지 않습니다."),
    REFRESH_TOKEN_INVALID(HttpStatus.UNAUTHORIZED, "AUTH-401-4", "RefreshToken이 유효하지 않습니다."),
    DORMANT_MEMBER(HttpStatus.UNAUTHORIZED, "AUTH-401-5", "휴면 상태입니다. Dooray 메시지의 인증번호를 입력해주세요."),
    INVALID_VERIFICATION_CODE(HttpStatus.UNAUTHORIZED, "AUTH-401-6", "인증번호가 올바르지 않습니다."),

    // 403
    ACCESS_DENIED(HttpStatus.FORBIDDEN, "AUTH-403", "접근 권한이 없습니다."),

    // 404
    MEMBER_NOT_FOUND(HttpStatus.NOT_FOUND, "AUTH-404", "회원을 찾을 수 없습니다."),

    // 500
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "AUTH-500-1", "서버 내부 오류가 발생했습니다."),
    TOKEN_PARSE_FAILED(HttpStatus.INTERNAL_SERVER_ERROR, "AUTH-500-2", "토큰 파싱에 실패했습니다."),
    DOORAY_MESSAGE_SEND_FAILED(HttpStatus.INTERNAL_SERVER_ERROR, "AUTH-500-3", "인증번호 전송에 실패했습니다.");

    private final HttpStatus status;
    private final String code;
    private final String message;
}
