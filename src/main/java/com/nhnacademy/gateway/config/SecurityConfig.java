package com.nhnacademy.gateway.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomSecurityContextRepository securityContextRepository;

    /**
     * 보안 필터 체인 설정
      - CSRF, 폼 로그인, HTTP Basic 인증 비활성화 -> API 게이트웨이로서 주로 API 요청을 처리하므로 필요하지 않음
      - 권한 설정 -> 로그인과 회원가입 엔드포인트는 인증없이 접근 허용, 그 외 모든 요청은 인증 필요
      - 커스텀 인증 필터 추가 -> X-User-Id 헤더에서 사용자 ID를 추출하여 인증 처리
     */
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http
    ) throws Exception {

        // 보안 설정
        http
                // CSRF 비활성화 -> API 게이트웨이로서 주로 API 요청을 처리하므로 CSRF 보호가 필요하지 않음
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                // 폼 로그인 비활성화 -> API 게이트웨이에서는 폼 로그인을 사용하지 않으므로 비활성화
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                // HTTP Basic 인증 비활성화 -> API 게이트웨이에서는 HTTP Basic 인증을 사용하지 않으므로 비활성화
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .securityContextRepository(securityContextRepository)

                // 권한 설정
                .authorizeExchange(exchanges->exchanges
                        // 로그인과 회원가입 엔드포인트는 인증없이 접근 허용
                        .pathMatchers("/api/accounts/login").permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/accounts/users").permitAll()
                        // 그 외 모든 요청은 인증 필요 -> X-User-Id 헤더를 통해 인증 처리
                        .anyExchange().authenticated()
                );

        return http.build();
    }
}
