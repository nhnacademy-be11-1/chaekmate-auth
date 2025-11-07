package com.nhnacademy.chaekmateauth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
public class JwtProperties {

    private String secret;
    private AccessToken access = new AccessToken();
    private RefreshToken refresh = new RefreshToken();

    @Getter
    @Setter
    public static class AccessToken {
        private Long exp;
    }

    @Getter
    @Setter
    public static class RefreshToken {
        private Long exp;
    }
}
