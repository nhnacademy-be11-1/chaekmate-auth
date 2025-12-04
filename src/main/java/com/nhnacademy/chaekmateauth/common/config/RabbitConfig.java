package com.nhnacademy.chaekmateauth.common.config;

import com.nhnacademy.chaekmateauth.common.properties.RabbitProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.DirectExchange;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class RabbitConfig {

    private final RabbitProperties rabbitProperties;

    @Bean
    public DirectExchange cartExchange() {
        return new DirectExchange(rabbitProperties.getExchange().getName());
    }

    @Bean
    public Queue loginQueue() {
        return new Queue(rabbitProperties.getQueues().getLoginQueueName(), true);
    }

    @Bean
    public Queue logoutQueue() {
        return new Queue(rabbitProperties.getQueues().getLogoutQueueName(), true);
    }

    @Bean
    public Jackson2JsonMessageConverter jsonMessageConverter() {
        return new Jackson2JsonMessageConverter();
    }

    @Bean
    public Binding loginBinding(Queue loginQueue, DirectExchange cartExchange) {
        return BindingBuilder.bind(loginQueue)
                .to(cartExchange)
                .with(rabbitProperties.getQueues().getLoginRoutingKey());
    }

    @Bean
    public Binding logoutBinding(Queue logoutQueue, DirectExchange cartExchange) {
        return BindingBuilder.bind(logoutQueue)
                .to(cartExchange)
                .with(rabbitProperties.getQueues().getLogoutRoutingKey());
    }
}
