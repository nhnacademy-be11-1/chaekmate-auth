package com.nhnacademy.chaekmateauth.common.config;

import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@ActiveProfiles("test")
@SuppressWarnings("NonAsciiCharacters")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class SwaggerConfigTest {

    private final SwaggerConfig swaggerConfig = new SwaggerConfig();

    @Test
    void authApi_Bean_생성_성공() {
        GroupedOpenApi api = swaggerConfig.authApi();

        assertThat(api).isNotNull();
        assertThat(api.getGroup()).isEqualTo("Auth API");
    }

    @Test
    void paycoApi_Bean_생성_성공() {
        GroupedOpenApi api = swaggerConfig.paycoApi();

        assertThat(api).isNotNull();
        assertThat(api.getGroup()).isEqualTo("PAYCO API");
    }

    @Test
    void dormantApi_Bean_생성_성공() {
        GroupedOpenApi api = swaggerConfig.dormantApi();

        assertThat(api).isNotNull();
        assertThat(api.getGroup()).isEqualTo("Dormant API");
    }
}

