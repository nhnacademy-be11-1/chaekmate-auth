package com.nhnacademy.chaekmateauth.client;

import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableFeignClients(basePackages = "com.nhnacademy.chaekmateauth.client")
public class FeignClientConfig {
}
