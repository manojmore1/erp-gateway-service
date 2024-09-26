package x.erp.security;


import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import x.erp.model.User;

@Service
public class UserService implements ReactiveUserDetailsService {

//    @Autowired
//    private UserRepository userRepository;

    public Mono<UserDetails> findByUsername(String username) {
//        return userRepository.findByUsername(username);
        User user = new User();
        user.setPassword("password1");
        user.setUsername(username);
        return Mono.just(user);
    }

    public Mono<User> save(User user) {
        user.setPassword(user.getPassword()); // Encrypt password before saving
//        return userRepository.save(user);
        return Mono.just(user);
    }
}
