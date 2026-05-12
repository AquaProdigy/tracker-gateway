package org.example.trackergateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.example.trackergateway.config.JwtProperties;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Slf4j
@Component
public class JwtAuthFilter implements GlobalFilter, Ordered {
    private static final String AUTH_HEADER = "Authorization";
    private static final String KEY_USERID = "userId";
    private static final String KEY_HEADER_USERID = "X-User-Id";
    private static final String BEARER_STARTWITH_TOKEN = "Bearer ";

    private final SecretKey signingKey;
    private final AntPathMatcher antPathMatcher;

    public JwtAuthFilter(JwtProperties jwtProperties) {
        this.antPathMatcher = new AntPathMatcher();
        this.signingKey = Keys.hmacShaKeyFor(
                jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8)
        );
    }


    private static final List<String> OPEN_PATH = List.of(
            "/auth/login",
            "/auth/register"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path =  exchange.getRequest().getURI().getPath();

        if (isOpenPath(path)) {
            return chain.filter(exchange);
        }

        String header = exchange.getRequest()
                .getHeaders()
                .getFirst(AUTH_HEADER);

        if (header == null || !header.startsWith(BEARER_STARTWITH_TOKEN)) {
            return unauthorized(exchange);
        }

        String token = header.substring(BEARER_STARTWITH_TOKEN.length());

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
        exchange.getResponse().getHeaders()
                .setContentType(MediaType.APPLICATION_JSON);
        DataBuffer buf = exchange.getResponse().bufferFactory()
                .wrap("{\"message\":\"Unauthorized\"}".getBytes());
        return exchange.getResponse().writeWith(Mono.just(buf));
    }

    private boolean isOpenPath(String path) {
        return  OPEN_PATH.stream().anyMatch(pattern -> antPathMatcher.match(pattern, path));
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
