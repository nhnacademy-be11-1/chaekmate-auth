package com.nhnacademy.chaekmateauth.common.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "rabbitmq")
public class RabbitProperties {

    private Exchange exchange;
    private Queues queues;

    @Getter
    @Setter
    public static class Exchange {
        private String name;
    }

    @Getter
    @Setter
    public static class Queues {
        private String loginQueueName;
        private String logoutQueueName;
        private String loginRoutingKey;
        private String logoutRoutingKey;
    }
}

