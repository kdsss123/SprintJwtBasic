package org.example.springjwt.service;

import org.example.springjwt.dto.JoinDTO;
import org.example.springjwt.entity.UserEntity;
import org.example.springjwt.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public void joinProcess(JoinDTO joinDTO) {
        String username = joinDTO.getUserName();
        String password = joinDTO.getPassword();

        Boolean isExist = userRepository.existsByUserName(username);

        if (isExist) {
            return;
        }

        UserEntity data = new UserEntity();

        data.setUserName(username);
        data.setPassword(bCryptPasswordEncoder.encode(password));
        data.setRole("ROLE_ADMIN");

        userRepository.save(data);
    }
}
