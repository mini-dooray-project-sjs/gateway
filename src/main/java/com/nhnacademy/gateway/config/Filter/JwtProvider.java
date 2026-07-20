package com.nhnacademy.gateway.config.Filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

/**
 * 토큰 생성, 검증, 파싱을 담당하는 클래스
 */
@Slf4j
@Component
public class JwtProvider {

    private final SecretKey secretKey;

    public JwtProvider(@Value("${jwt.secret-key}") String secretKeyString) {
        byte[] keyBytes=Decoders.BASE64.decode(secretKeyString);
        this.secretKey= Keys.hmacShaKeyFor(keyBytes);
    }

    // 토큰 검증 -> 유효한 토큰인지, 만료되었는지 검사
    public boolean validateToken(String token) {
        try {
            getClaims(token);
            return true; // 토큰이 유효하면 true 반환
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            return false; // 토큰이 유효하지 않으면 false 반환
        }
    }

    // 토큰에서 userId 추출
    public String getUserIdFromToken(String token) {
        return getClaims(token).getSubject(); // 토큰의 주체(subject)에서 userId 추출
    }

    // 토큰에서 role 추출
    public String getRoleFromToken(String token) {
        return getClaims(token).get("role", String.class); // 토큰의 클레임에서 role 추출
    }

    // 토큰에서 남은 유효 기간 계산
    public Long getRemainingTime(String token) {
        try {
            Date expiration=getClaims(token).getExpiration(); // 토큰의 만료 시간 추출
            long now=new Date().getTime();
            return expiration.getTime()-now; // 남은 유효 기간 계산 (만료 시간 - 현재 시간)
        } catch(JwtException e) {
            return 0L; // 토큰이 유효하지 않으면 남은 시간 0 반환
        }
    }

    // 토큰에서 클레임(정보) 추출
    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)      // 토큰 서명 검증에 사용할 비밀 키 설정
                .build()                    // JWT 파서 빌드
                .parseSignedClaims(token)   // 파싱 시도 - 서명된 클레임을 파싱
                .getPayload();              // 파싱 성공 시, 클레임(토큰의 내용) 반환
    }
}
