package com.clientRackr.api.servicesImpl;

import com.clientRackr.api.entity.User;
import com.clientRackr.api.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByEmail(email);
        User userDetail = user.get();
        UserDetails userDetails =
                org.springframework.security.core.userdetails.
                        User.builder()
                        .username(userDetail.getEmail())
                        .password(userDetail.getPassword())
                .build();
        return userDetails;
    }
}
