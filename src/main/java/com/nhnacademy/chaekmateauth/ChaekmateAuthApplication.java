package com.nhnacademy.chaekmateauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@ConfigurationPropertiesScan
@SpringBootApplication
public class ChaekmateAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(ChaekmateAuthApplication.class, args);
    }

}
