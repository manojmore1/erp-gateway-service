package x.erp.security.exception;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Objects;

@Component
public class AuthenticationExceptionHandler implements ServerAuthenticationEntryPoint{
    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException e) {
        String platform = exchange.getRequest().getHeaders().getFirst("platform");
        if (Objects.nonNull(platform) && platform.endsWith("apiplatform")) {
            return Mono.fromRunnable(() -> {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                // Optionally set a custom response body (e.g., error message in JSON)
                exchange.getResponse().getHeaders().add("Content-Type", "application/json");
                exchange.getResponse().setComplete();
            });
        } else {
            // Set response status to redirect to the login page
            exchange.getResponse().setStatusCode(HttpStatus.FOUND); // Use 302 for redirect

            // Redirect to login page
            exchange.getResponse().getHeaders().setLocation(URI.create("/page/login.html"));
            return Mono.empty();  // Return empty Mono to indicate completion
        }

    }
}
