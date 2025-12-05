package com.nhnacademy.chaekmateauth.common.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.models.info.Info;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @io.swagger.v3.oas.annotations.info.Info(
                title = "chaekmate auth API",
                version = "v1",
                description = "chaekmate auth 서버 API 문서"
        )
)
public class SwaggerConfig {

    @Bean
    public GroupedOpenApi authApi() {
        return GroupedOpenApi.builder()
                .group("Auth API")
                .addOpenApiCustomizer(openApi -> openApi
                        .info(new Info()
                                .title("인증 관련 API")
                                .description("회원/관리자 로그인, 로그아웃, 토큰 갱신, 회원 정보 조회 기능")
                                .version("v1.0")))
                .pathsToMatch("/auth/login", "/auth/admin/login", "/auth/logout", "/auth/refresh", "/auth/me")
                .build();
    }

    @Bean
    public GroupedOpenApi paycoApi() {
        return GroupedOpenApi.builder()
                .group("PAYCO API")
                .addOpenApiCustomizer(openApi -> openApi
                        .info(new Info()
                                .title("PAYCO OAuth 관련 API")
                                .description("PAYCO OAuth 인증, 콜백 처리, 임시 정보 관리 기능")
                                .version("v1.0")))
                .pathsToMatch("/auth/payco/**")
                .build();
    }

    @Bean
    public GroupedOpenApi dormantApi() {
        return GroupedOpenApi.builder()
                .group("Dormant API")
                .addOpenApiCustomizer(openApi -> openApi
                        .info(new Info()
                                .title("휴면 계정 관련 API")
                                .description("휴면 계정 해제 인증 및 활성화 기능")
                                .version("v1.0")))
                .pathsToMatch("/auth/dormant/**")
                .build();
    }
}

