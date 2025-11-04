package com.nhnacademy.chaekmateauth.exception;

import lombok.Getter;

@Getter
public class AuthException extends RuntimeException{

    private final BaseErrorCode errorCode;

    public AuthException(BaseErrorCode errorCode, Throwable cause) {
        super(errorCode.getMessage(), cause);
        this.errorCode = errorCode;
    }
    public AuthException(BaseErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }
}
