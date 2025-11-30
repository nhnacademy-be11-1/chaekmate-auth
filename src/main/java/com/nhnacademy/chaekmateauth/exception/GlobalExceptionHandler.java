package com.nhnacademy.chaekmateauth.exception;

import com.nhnacademy.chaekmateauth.dto.response.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import shop.chaekmate.common.log.logging.Log;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ErrorResponse> handleAuthException(AuthException e) {
        log.warn("[AuthException] {}", e.getMessage());
        BaseErrorCode errorCode = e.getErrorCode();
        Log.Error(e, errorCode.getStatus().value());
        return ResponseEntity.status(errorCode.getStatus())
                .body(ErrorResponse.from(errorCode));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpected(Exception e) {
        log.error("[Unexpected Exception]", e);
        BaseErrorCode errorCode = AuthErrorCode.INTERNAL_SERVER_ERROR;
        Log.Error(e, errorCode.getStatus().value());
        return ResponseEntity.status(errorCode.getStatus())
                .body(ErrorResponse.from(errorCode));
    }
}
