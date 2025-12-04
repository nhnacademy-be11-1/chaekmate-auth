package com.nhnacademy.chaekmateauth.common.config;

import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;

@ActiveProfiles("test")
@SuppressWarnings("NonAsciiCharacters")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class RedisConfigTest {

    @Test
    void redisTemplate_Bean_생성_성공() {
        RedisConfig redisConfig = new RedisConfig();
        RedisConnectionFactory connectionFactory = org.mockito.Mockito.mock(RedisConnectionFactory.class);

        RedisTemplate<String, String> redisTemplate = redisConfig.redisTemplate(connectionFactory);

        assertThat(redisTemplate).isNotNull();
        assertThat(redisTemplate.getConnectionFactory()).isEqualTo(connectionFactory);
    }

    @Test
    void restTemplate_Bean_생성_성공() {
        RedisConfig redisConfig = new RedisConfig();

        RestTemplate restTemplate = redisConfig.restTemplate();

        assertThat(restTemplate).isNotNull();
    }
}

