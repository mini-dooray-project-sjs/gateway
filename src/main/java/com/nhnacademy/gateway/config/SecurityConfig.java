package com.nhnacademy.gateway.config;

import com.nhnacademy.gateway.config.Filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

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
                // 세션 관리 -> API 게이트웨이에서는 세션 사용 X -> 세션 저장소 비활성화
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                // 권한 설정
                .authorizeExchange(exchanges-> exchanges
                        // 로그인, 로그아웃, 토큰 갱신 엔드포인트는 인증 없이 접근 허용
                        .pathMatchers("/api/auth/login", "/api/auth/refresh", "/api/auth/logout").permitAll()
                        // 회원가입 엔드포인트는 인증 없이 접근 허용
                        .pathMatchers(HttpMethod.POST, "/api/accounts/users").permitAll()
                        // 그 외 모든 요청은 인증 필요
                        .anyExchange().authenticated()
                )
                // 커스텀 인증 필터 추가 -> jwt 인증 필터를 SecurityWebFiltersOrder.AUTHENTICATION 위치에 추가하여 인증 처리
                .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION);

        return http.build();
    }
}
