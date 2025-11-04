package com.nhnacademy.chaekmateauth.exception;

import java.io.Serializable;
import org.springframework.http.HttpStatus;

public interface BaseErrorCode extends Serializable {
    HttpStatus getStatus();
    String getCode();
    String getMessage();
}
