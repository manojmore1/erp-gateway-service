package x.erp.security;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

@Component
public class CustomLogoutHandler implements ServerLogoutHandler {

    @Override
    public Mono<Void> logout(WebFilterExchange webFilterExchange, Authentication authentication) {
        ServerWebExchange exchange = webFilterExchange.getExchange();

        // Check the request header to determine if it's an API request or a browser request
        String acceptHeader = exchange.getRequest().getHeaders().getFirst("Accept");

        if (acceptHeader != null && acceptHeader.contains("application/json")) {
            // If it's an API request, return a JSON response
            exchange.getResponse().setStatusCode(HttpStatus.OK);
            exchange.getResponse().getHeaders().add("Content-Type", "application/json");
            return exchange.getResponse().writeWith(
                    Mono.just(exchange.getResponse().bufferFactory().wrap("{\"message\": \"Successfully logged out\"}".getBytes()))
            );
        } else {
//            // If it's a browser request, redirect to the login page
//            exchange.getResponse().setStatusCode(HttpStatus.FOUND); // 302 Redirect
//            exchange.getResponse().getHeaders().setLocation(URI.create("/page/login.html"));
            return Mono.empty();
        }
    }

}
