package com.nhnacademy.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.serializer.GenericJacksonJsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;

@Configuration
public class RedisSessionSerializerConfig {

    /**
     * 스프링 세션이 레디스에 객체를 저장할 때 자바 기본 직렬화 대신 JSON 형태로 저장하도록 설정합니다.
     */
    @Bean(name="springSessionDefaultRedisSerializer")
    public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
        return GenericJacksonJsonRedisSerializer.builder().build();
    }
}