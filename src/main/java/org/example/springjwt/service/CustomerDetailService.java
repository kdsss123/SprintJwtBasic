package org.example.springjwt.service;

import org.example.springjwt.dto.CustomerUserDetails;
import org.example.springjwt.entity.UserEntity;
import org.example.springjwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomerDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomerDetailService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity userData = userRepository.findByUsername(username);

        if(userData != null) {
            return new CustomerUserDetails(userData);
        }

        return null;
    }
}
