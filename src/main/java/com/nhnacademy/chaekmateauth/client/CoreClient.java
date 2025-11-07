package com.nhnacademy.chaekmateauth.client;

import com.nhnacademy.chaekmateauth.dto.MemberResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Component
@FeignClient(name = "core-server")
public interface CoreClient {
    @GetMapping(value = "/members/login-id")
    MemberResponse getMemberByLoginId(@RequestParam("loginId") String loginId);
}
