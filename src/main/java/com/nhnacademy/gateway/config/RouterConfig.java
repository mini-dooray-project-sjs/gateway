package com.nhnacademy.gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;

@Configuration
public class RouterConfig {

    @Value("${external.auth-api.uri}")
    private String authApiUrl;

    @Value("${external.task-api.uri}")
    private String taskApiUrl;

    @Value("${external.account-api.uri}")
    private String accountApiUrl;

    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder) {
        return builder.routes()

                // auth 라우팅 -> 모든 /api/auth/** 경로에 대해 인증 없이 authApiUrl로 라우팅
                .route("auth-api",
                        p-> p.path("/api/auth/**")
                                .uri(authApiUrl))

                // task 라우팅 -> 모든 /api/tasks/** 경로에 대해 useridHeaderFilter를 적용하여 X-User-Id 헤더에 사용자 ID를 추가한 후 taskApiUrl로 라우팅
                .route("task-api",
                        p->p.path("/api/tasks/**")
                                .filters(f->f.filter(useridHeaderFilter()))
                                .uri(taskApiUrl))

                // 회원가입 라우팅 -> 회원가입 인증없이 접근 허용
                .route("account-register",
                        p->p.path("/api/accounts/users")
                                .and()
                                .method(HttpMethod.POST)
                                .uri(accountApiUrl))
                // account 라우팅 -> 모든 /api/accounts/** 경로에 대해 useridHeaderFilter를 적용하여 X-User-Id 헤더에 사용자 ID를 추가한 후 accountApiUrl로 라우팅
                .route("account-api",
                        p->p.path("/api/accounts/**")
                                .filters(f->f.filter(useridHeaderFilter()))
                                .uri(accountApiUrl))

                .build();
    }

    /**
     * 사용자 ID를 X-User-Id 헤더에 추가하는 필터
     * ReactiveSecurityContextHolder를 사용하여 현재 인증된 사용자의 정보를 가져와서 X-User-Id 헤더에 사용자 ID를 추가
      - 인증된 사용자가 없는 경우에는 헤더를 추가하지 않고 다음 필터로 넘어감
     */
    private GatewayFilter useridHeaderFilter() {
        return (exchange, chain) -> ReactiveSecurityContextHolder.getContext()
                // 인증된 사용자 정보 가져오기 -> ReactiveSecurityContextHolder에서 현재 보안 컨텍스트를 가져와서 인증 정보를 추출
                .map(securityContext -> securityContext.getAuthentication())
                // 인증된 사용자가 있는 경우 -> 인증된 사용자가 있는 경우에는 사용자 ID와 역할을 추출하여 X-User-Id 헤더에 추가한 새로운 요청으로 다음 필터 체인 실행
                .flatMap(authentication -> {
                    // 사용자 ID 추출
                    String userId=authentication.getName();

                    // 역할 추출
                    String role=authentication.getAuthorities().stream()
                            .findFirst()
                            .map(grantedAuthority -> grantedAuthority.getAuthority())
                            .orElse("ROLE_USER");

                    // 헤더가 추가된 새로운 요청 생성 -> 기존 요청을 변형하여 X-User-Id 헤더에 사용자 ID와 역할을 추가한 새로운 요청 생성
                    var mutateRequest=exchange.getRequest().mutate()
                            .header("X-USER-ID", userId)
                            .header("X-USER-ROLE", role)
                            .build();

                    // 변형된 요청으로 새로운 교환 객체 생성 -> 기존 교환 객체를 변형하여 새로운 요청을 포함하는 새로운 교환 객체 생성
                    var mutateExchange=exchange.mutate().request(mutateRequest).build();

                    // 변형된 교환 객체로 다음 필터 체인 실행 -> 변형된 교환 객체를 사용하여 다음 필터 체인 실행
                    return chain.filter(mutateExchange);
                })
                // 인증된 사용자가 없는 경우 -> 인증된 사용자가 없는 경우에는 헤더를 추가하지 않고 다음 필터로 넘어감
                .switchIfEmpty(chain.filter(exchange));
    }
}
