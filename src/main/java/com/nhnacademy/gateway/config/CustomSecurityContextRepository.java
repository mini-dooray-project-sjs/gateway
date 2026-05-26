package com.nhnacademy.gateway.config;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;

@Component
@RequiredArgsConstructor
public class CustomSecurityContextRepository implements ServerSecurityContextRepository {

    private final ReactiveStringRedisTemplate redisTemplate;

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        return Mono.empty();
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        HttpCookie sessionCookie = exchange.getRequest().getCookies().getFirst("SESSION");
        if (sessionCookie == null) {
            return Mono.empty();
        }

        try {
            String base64SessionId = sessionCookie.getValue();
            String decodedId = new String(Base64.getDecoder().decode(base64SessionId));

            String redisKey = "spring:session:sessions:" + decodedId;

            return redisTemplate.<String, String>opsForHash()
                    .multiGet(redisKey, Arrays.asList("sessionAttr:X-User-Id", "sessionAttr:X-User-Role"))
                    .flatMap(values -> {
                        String userId = values.get(0);
                        String role = values.get(1);

                        if (userId != null && userId.startsWith("\"") && userId.endsWith("\"")) {
                            userId = userId.substring(1, userId.length() - 1);
                        }
                        if (role != null && role.startsWith("\"") && role.endsWith("\"")) {
                            role = role.substring(1, role.length() - 1);
                        }

                        if (userId != null && !userId.isEmpty() && !userId.equals("null")) {
                            String authority = role != null && role.startsWith("ROLE_") ? role : "ROLE_" + role;
                            Authentication authentication = new UsernamePasswordAuthenticationToken(
                                    userId,
                                    null,
                                    Collections.singletonList(new SimpleGrantedAuthority(authority))
                            );
                            return Mono.just(new SecurityContextImpl(authentication));
                        }

                        return Mono.empty();
                    });
        } catch (Exception e) {
            System.out.println("쿠키 해독 중 에러 발생: " + e.getMessage());
            return Mono.empty();
        }
    }
}