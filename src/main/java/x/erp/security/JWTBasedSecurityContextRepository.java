package x.erp.security;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class JWTBasedSecurityContextRepository implements ServerSecurityContextRepository {

    private final JWTAuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    public JWTBasedSecurityContextRepository(JWTAuthenticationManager authenticationManager, JWTUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        // No-op: SecurityContext saving is not required for JWT (stateless auth)
        return Mono.empty();
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        // Extract the Authorization header
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

        // Check if the header contains a Bearer token
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            // Validate the token and authenticate the user
            Authentication auth = new UsernamePasswordAuthenticationToken(token, token);

            // Delegate authentication to the AuthenticationManager
            return this.authenticationManager.authenticate(auth)
                    .map(SecurityContextImpl::new);  // Wrap the authentication in a SecurityContext
        }

        // If no valid token, return empty
        return Mono.empty();
    }
}

