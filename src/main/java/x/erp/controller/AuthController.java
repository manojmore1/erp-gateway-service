package x.erp.controller;
//import org.springframework.security.access.prepost.PreAuthorize;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import x.erp.model.AuthRequest;
import x.erp.model.AuthResponse;
import x.erp.model.User;
import x.erp.security.JWTUtil;
import x.erp.security.TokenBlacklistService;
import x.erp.security.UserService;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    @Autowired
    private JWTUtil jwtUtil;

    private final TokenBlacklistService tokenBlacklistService;

    @Autowired
    private UserService userService;

    public AuthController(TokenBlacklistService tokenBlacklistService) {
        this.tokenBlacklistService = tokenBlacklistService;
    }

    @GetMapping("/welcome")
    public String welcome() {
        return "Welcome, this endpoint is not secure";
    }

    @GetMapping("/user/userProfile")
    @PreAuthorize("hasRole('USER')")  // Use hasRole for role-based access control
    public String userProfile() {
        return "Welcome to User Profile";
    }

    @GetMapping("/admin/adminProfile")
    @PreAuthorize("hasRole('ADMIN')")  // Use hasRole for role-based access control
    public String adminProfile() {
        return "Welcome to Admin Profile";
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> login(@RequestBody AuthRequest authRequest, ServerWebExchange exchange) {
        return userService.findByUsername(authRequest.getUsername())
                .map(userDetails -> {
                    if (userDetails.getPassword().equals(authRequest.getPassword())) {
                        String token = jwtUtil.generateToken(authRequest.getUsername());
                        log.info("=========TOKEN: {}", token);

//                        String value = Base64.getEncoder().encodeToString(("Bearer "+token).getBytes());
                        String value = URLEncoder.encode("Bearer "+token, StandardCharsets.UTF_8);
                        // Create a cookie and store the JWT token
                        ResponseCookie cookie = ResponseCookie.from("Authorization", value)
                                .httpOnly(true)       // Prevent JavaScript access (helps mitigate XSS attacks)
                                //.secure(true)         // Use HTTPS
                                .path("/")            // Cookie available to all paths
                                .maxAge(3600)         // Set expiration time (in seconds)
                                //.sameSite("Strict")   // Prevent CSRF (Cross-Site Request Forgery)
                                .build();

                        exchange.getResponse().addCookie(cookie);
                        return ResponseEntity.ok(new AuthResponse(value));
                    } else {
                        throw new BadCredentialsException("Invalid username or password");
                    }
                }).switchIfEmpty(Mono.error(new BadCredentialsException("Invalid username or password")));
    }
    @PostMapping("/signup")
    public Mono<ResponseEntity<String>> signup(@RequestBody User user) {
        // Encrypt password before saving
        user.setPassword(user.getPassword());
        return userService.save(user)
                .map(savedUser -> ResponseEntity.ok("User signed up successfully"));
    }

    @GetMapping("/protected")
    public Mono<ResponseEntity<String>> protectedEndpoint() {
        return Mono.just(ResponseEntity.ok("You have accessed a protected endpoint!"));
    }


}
