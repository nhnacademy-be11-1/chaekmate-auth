package com.nhnacademy.chaekmateauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.cloud.openfeign.EnableFeignClients;

@ConfigurationPropertiesScan
@SpringBootApplication
@EnableFeignClients
public class ChaekmateAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(ChaekmateAuthApplication.class, args);
    }

}
