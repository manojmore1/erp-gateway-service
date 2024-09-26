package x.erp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;

import org.springframework.security.config.web.server.ServerHttpSecurity;


import org.springframework.security.web.server.SecurityWebFilterChain;
import x.erp.security.*;


@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    @Autowired
    UserService userService;

    @Autowired
    JWTUtil jwtUtil;

    public static final String[] PERMITTED_URL = new String[]{
            "/auth/welcome",
            "api/organizations",
            "/actuator/**",
            "/auth/login",
            "/auth/signup"
    };

    private final JWTAuthenticationManager authenticationManager;

    public SecurityConfig(JWTAuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

//    @Bean
//    @Primary
//    public ReactiveAuthenticationManager jwtAuthenticationManager() {
//        return new JWTAuthenticationManager(jwtUtil, userService);
//    }


    @Bean
    @Primary
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

        // Disabling CSRF as WebFlux API's typically do not use sessions or cookies
        return http.securityContextRepository(new JWTBasedSecurityContextRepository(authenticationManager, jwtUtil))
                .authenticationManager(authenticationManager)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/auth/protected")
                        .authenticated()
                        .anyExchange()
                        .permitAll()
                )
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .build();
    }

//    @Bean
//    public MapReactiveUserDetailsService userDetailsService() {
//        // In-memory user store
//        UserDetails user = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER")
//                .build();
//
//        UserDetails admin = User.withDefaultPasswordEncoder()
//                .username("admin")
//                .password("admin")
//                .roles("ADMIN")
//                .build();
//
//        return new MapReactiveUserDetailsService(user, admin);
//    }
}
