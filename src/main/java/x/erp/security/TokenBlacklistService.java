package x.erp.security;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import java.util.HashSet;
import java.util.Set;

@Service
public class TokenBlacklistService {

    // Use Redis or other persistent storage in a real scenario
    private Set<String> blacklistedTokens = new HashSet<>();

    public Mono<Void> blacklistToken(String token) {
        blacklistedTokens.add(token);
        return Mono.empty();
    }

    public Mono<Boolean> isTokenBlacklisted(String token) {
        return Mono.just(blacklistedTokens.contains(token));
//        return Mono.just(true);
    }
}

