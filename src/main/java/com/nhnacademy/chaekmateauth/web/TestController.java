package com.nhnacademy.chaekmateauth.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/* Gateway & Eureka 연결 테스트를 위한 Controller */
@RestController
@RequestMapping("/test")
public class TestController {

    @Value("${server.port}")
    private String port;

    @GetMapping
    public String getTest() {
        return "Auth Test Port: " + this.port;
    }
}
