package com.nhnacademy.chaekmateauth.common.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "payco.oauth")
@Getter
@Setter
public class PaycoOAuthProperties {

    private String clientId;
    private String clientSecret;
    private String redirectUri;
}