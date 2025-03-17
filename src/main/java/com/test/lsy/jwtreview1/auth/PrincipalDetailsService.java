package com.test.lsy.jwtreview1.auth;

import com.test.lsy.jwtreview1.model.User;
import com.test.lsy.jwtreview1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User findUser = repository.findByUsername(username);

        if(findUser == null) {
            log.error("User not found username: {}", username);
            throw new UsernameNotFoundException("User not found with username: {} " + username);
        }

        log.info("User found with username : {}", username);
        return new PrincipalDetails(findUser);
    }
}
