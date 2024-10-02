package x.erp.security.exception;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
@Component
public class AuthenticationExceptionHandler implements ServerAuthenticationEntryPoint{
    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException e) {
        return Mono.fromRunnable(() -> {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            // Optionally set a custom response body (e.g., error message in JSON)
            exchange.getResponse().getHeaders().add("Content-Type", "application/json");
            exchange.getResponse().setComplete();
        });
    }
}
