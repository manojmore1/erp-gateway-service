//package x.erp.security;
//
//import org.springframework.security.authentication.ReactiveAuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.context.ReactiveSecurityContextHolder;
//import org.springframework.security.core.context.SecurityContext;
//import org.springframework.security.core.context.SecurityContextImpl;
//import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
//import org.springframework.security.web.server.context.ServerSecurityContextRepository;
//import org.springframework.stereotype.Component;
//import reactor.core.publisher.Mono;
//
////@Component
//public class JwtAuthenticationWebFilter extends AuthenticationWebFilter {
//
//    public JwtAuthenticationWebFilter(ReactiveAuthenticationManager authenticationManager) {
//        super(authenticationManager);
//        setServerAuthenticationConverter(exchange -> Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst("Authorization"))
//                .flatMap(authHeader -> {
//                    if (authHeader.startsWith("Bearer ")) {
//                        String token = authHeader.substring(7);
//                        return Mono.just(new UsernamePasswordAuthenticationToken(token, token));
//                    }
//                    return Mono.empty();
//                }));
//    }
//}
//
