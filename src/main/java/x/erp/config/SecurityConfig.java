package x.erp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;

import org.springframework.security.config.web.server.ServerHttpSecurity;


import org.springframework.security.web.server.SecurityWebFilterChain;
import x.erp.security.*;
import x.erp.security.exception.AuthenticationExceptionHandler;
import x.erp.security.exception.CustomAccessDeniedHandler;


@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    @Autowired
    UserService userService;

    @Autowired
    JWTUtil jwtUtil;

    @Autowired
    private AuthenticationExceptionHandler authenticationExceptionHandler;

    private final TokenBlacklistService tokenBlacklistService;

    private final CustomLogoutHandler customLogoutHandler;

    private final CustomLogoutSuccessHandler customLogoutSuccessHandler;

    @Autowired
    private CustomAccessDeniedHandler accessDeniedHandler;

    public static final String[] PERMITTED_URL = new String[]{
            "/page/**",
            "/signup",
            "/actuator/**",
            "/auth/**"
    };

    private final JWTAuthenticationManager authenticationManager;

    public SecurityConfig(JWTAuthenticationManager authenticationManager, TokenBlacklistService tokenBlacklistService,
                          CustomLogoutHandler customLogoutHandler, CustomLogoutSuccessHandler customLogoutSuccessHandler) {
        this.authenticationManager = authenticationManager;
        this.tokenBlacklistService = tokenBlacklistService;
        this.customLogoutHandler = customLogoutHandler;
        this.customLogoutSuccessHandler = customLogoutSuccessHandler;
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
        return http.securityContextRepository(new JWTBasedSecurityContextRepository(authenticationManager, jwtUtil, tokenBlacklistService))
                .authenticationManager(authenticationManager)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(PERMITTED_URL).permitAll().anyExchange().authenticated()
                ).exceptionHandling(exceptionHandlingSpec -> exceptionHandlingSpec
                        .authenticationEntryPoint(authenticationExceptionHandler)  // Custom AuthenticationEntryPoint
                        .accessDeniedHandler(accessDeniedHandler)  // Custom AccessDeniedHandler
                ).logout(logout -> {
                    logout.logoutUrl("/auth/logout");
                    logout.logoutHandler(customLogoutHandler);
                    logout.logoutSuccessHandler(customLogoutSuccessHandler);
                })
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
