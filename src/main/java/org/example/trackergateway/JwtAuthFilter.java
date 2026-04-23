package org.example.trackergateway;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter implements GlobalFilter, Ordered {
    private static final String AUTH_HEADER = "Authorization";
    private static final String KEY_USERID = "userId";
    private static final String KEY_HEADER_USERID = "X-User-Id";
    private static final String BEARER_STARTWITH_TOKEN = "Bearer ";
    private static final Integer TOKEN_SUBSTRING_LENGTH = 7;

    @Value("${jwt.secret}")
    private String jwtSecret;

    private SecretKey signingKey;

    private static final List<String> OPEN_PATH = List.of(
            "/auth/login",
            "/auth/register"
    );

    @PostConstruct
    private void init() {
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        log.info("JWT Signing Key initialized successfully.");
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path =  exchange.getRequest().getURI().getPath();

        if (OPEN_PATH.contains(path)) {
            return chain.filter(exchange);
        }

        String header = exchange.getRequest()
                .getHeaders()
                .getFirst(AUTH_HEADER);

        if (header == null || !header.startsWith(BEARER_STARTWITH_TOKEN)) {
            return unauthorized(exchange);
        }

        String token = header.substring(TOKEN_SUBSTRING_LENGTH);

        Claims claims;
        try {
            claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        }catch (JwtException e){
            return unauthorized(exchange);
        }

        Long userId = claims.get(KEY_USERID, Long.class);

        if (userId == null) {
            return unauthorized(exchange);
        }

        ServerHttpRequest mutated = exchange.getRequest().mutate()
                .headers(h -> h.remove(KEY_HEADER_USERID))
                .header(KEY_HEADER_USERID, userId.toString())
                .build();

        return chain.filter(exchange.mutate().request(mutated).build());
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
