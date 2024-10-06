package x.erp.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;


public class JWTBasedSecurityContextRepository implements ServerSecurityContextRepository {

    private static final Logger log = LoggerFactory.getLogger(JWTBasedSecurityContextRepository.class);
    private final JWTAuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;
    private final TokenBlacklistService tokenBlacklistService;


    public JWTBasedSecurityContextRepository(JWTAuthenticationManager authenticationManager, JWTUtil jwtUtil, TokenBlacklistService tokenBlacklistService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.tokenBlacklistService = tokenBlacklistService;
    }

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        // No-op: SecurityContext saving is not required for JWT (stateless auth)
        return Mono.empty();
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        // Extract the Authorization header
        String headerAuthToken = exchange.getRequest().getHeaders().getFirst("Authorization");
        HttpCookie httpCookie = exchange.getRequest().getCookies().getFirst("Authorization");
        String cookieAuthToken = Objects.nonNull(httpCookie)? httpCookie.getValue() : null;
        String authHeader = Objects.isNull(headerAuthToken)? cookieAuthToken : headerAuthToken;

        log.info("======authHeader: {}", authHeader);
        Mono<SecurityContext> securityContext = null;

        // Check if the header contains a Bearer token
        if (authHeader != null && authHeader.startsWith("Bearer")) {
            authHeader = URLDecoder.decode(authHeader, StandardCharsets.UTF_8);
            String token = authHeader.substring(7);
            log.info("====Received TOKEN: {}", token);
            securityContext = tokenBlacklistService.isTokenBlacklisted(token).flatMap(isBlackListed -> {
                if(isBlackListed) {
                    return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token Expired by Logout"));
                }
                // Validate the token and authenticate the user
                Authentication auth = new UsernamePasswordAuthenticationToken(token, token);

                // Delegate authentication to the AuthenticationManager
                return this.authenticationManager.authenticate(auth)
                        .flatMap(resp -> {
                            exchange.getResponse().getHeaders().add("X-Success", "Authenticated");
                            return Mono.just((SecurityContext) new SecurityContextImpl(resp));
                        })  // Wrap the authentication in a SecurityContext
                        .onErrorMap(
                                er -> er instanceof AuthenticationException,
                                autEx -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, autEx.getMessage(), autEx)
                        );
            });

            return securityContext;
        }

        // If no valid token, return empty
        return Mono.empty();
    }
}

