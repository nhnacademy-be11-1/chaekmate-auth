package com.nhnacademy.chaekmateauth.client;

import com.nhnacademy.chaekmateauth.dto.request.DoorayMessageRequest;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "dooray-client", url = "${dooray.webhook.url}")
public interface DoorayClient {

    @PostMapping
    String sendMessage(@RequestBody DoorayMessageRequest request);
}
