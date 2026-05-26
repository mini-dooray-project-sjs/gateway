package com.nhnacademy.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.session.data.redis.config.annotation.web.server.EnableRedisWebSession;

@SpringBootApplication
@EnableRedisWebSession
public class MinidoorayGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(MinidoorayGatewayApplication.class, args);
    }

}
