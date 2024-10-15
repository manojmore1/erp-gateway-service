package x.erp.security;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class CustomLogoutSuccessHandler implements ServerLogoutSuccessHandler {

    @Override
    public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
        var response = exchange.getExchange().getResponse();

        // Set HTTP status to 302 (Found) for redirection
        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().set(HttpHeaders.LOCATION, "/page/login.html");

        // Complete the response processing
        return response.setComplete();
    }
}

