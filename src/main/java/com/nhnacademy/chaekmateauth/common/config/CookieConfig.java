package com.nhnacademy.chaekmateauth.common.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class CookieConfig {

    @Value("${spring.profiles.active}")
    private String activeProfile;

    public boolean isSecureCookie() {
        // prod면 true, dev면 false
        return !"dev".equalsIgnoreCase(activeProfile);
    }
}