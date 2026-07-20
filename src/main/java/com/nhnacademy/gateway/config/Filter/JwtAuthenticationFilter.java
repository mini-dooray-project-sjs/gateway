package com.nhnacademy.gateway.config.Filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Collections;

/**
 * 게이트웨이로 들어오는 모든 요청의 헤더를 검사
 * JWT 토큰이 존재하는 경우, 토큰의 유효성 검사 및 Redis에 저장된 블랙리스트 여부를 확인
 * 토큰이 존재하지 않거나, 유효하지 않거나, 블랙리스트에 등록된 경우, 401 Unauthorized 응답을 반환
 * 유효한 토큰인 경우, 요청을 다음 필터 체인으로 전달
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtProvider jwtProvider;
    private final ReactiveStringRedisTemplate redisTemplate;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path=exchange.getRequest().getURI().getPath();

        // 로그인, 회원가입, 토큰 갱신 요청은 인증 없이 허용
        if(path.equals("/api/auth/login") || path.equals("/api/auth/refresh") || path.equals("/api/auth/logout") ||
                (path.equals("/api/accounts/users") && exchange.getRequest().getMethod().matches("POST"))) {
            return chain.filter(exchange);
        }

        // 요청 헤더에서 Authorization 헤더 추출
        String authHeader=exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if(authHeader==null||!authHeader.startsWith("Bearer ")) {
            // 401 Unauthorized 응답 반환
            log.warn("토큰이 존재하지 않거나, 잘못된 형식입니다.");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String accessToken=authHeader.substring(7);

        // 토큰 자체의 유효성 검사
        if(!jwtProvider.validateToken(accessToken)) {
            log.warn("유효하지 않은 토큰입니다.");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Redis에 저장된 블랙리스트 여부 확인
        String redisKey="blacklist:"+accessToken;

        // Redis에서 해당 토큰이 블랙리스트에 등록되어 있는지 확인
        return redisTemplate.hasKey(redisKey)
                // 블랙리스트 여부에 따라 처리
                .flatMap(isBlacklisted -> {
                    // 블랙리스트에 등록된 토큰인 경우, 401 Unauthorized 응답 반환
                    if(isBlacklisted) {
                        log.warn("로그아웃 처리된 토큰입니다.");
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    }

                    // 토큰이 유효한 경우, 토큰에서 사용자 정보 추출
                    String userId= jwtProvider.getUserIdFromToken(accessToken);
                    String role= jwtProvider.getRoleFromToken(accessToken);

                    // SecurityContext에 인증 정보 저장 (인증 객체 생성)
                    Authentication authentication=new UsernamePasswordAuthenticationToken(
                            userId, null, Collections.singletonList(new SimpleGrantedAuthority(role))
                    );
                    SecurityContext context=new SecurityContextImpl(authentication);

                    // 다음 필터 체인으로 요청 전달, SecurityContext를 Reactor Context에 저장하여 이후 인증 정보 활용 가능
                    return chain.filter(exchange)
                            .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(context)));
                });
    }
}
