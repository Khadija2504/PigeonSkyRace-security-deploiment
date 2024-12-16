package com.PigeonSkyRace.Pigeon.service.impl;

import com.PigeonSkyRace.Pigeon.model.User;
import com.PigeonSkyRace.Pigeon.repository.UserRepository;
import com.PigeonSkyRace.Pigeon.service.UserService;
import com.PigeonSkyRace.Pigeon.util.PasswordUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public User createBreeder(User breeder) {
        String hashedPassword = PasswordUtil.hashPassword(breeder.getPassword());
        breeder.setPassword(hashedPassword);
        return userRepository.save(breeder);
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public User getBreederById(int breederId) {
        return userRepository.findById(breederId)
                .orElseThrow(() -> new IllegalArgumentException("no breeder found with id: " + breederId));
    }

    @Override
    public User updateUser(String email, String role) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            user.setRole(role);
            return userRepository.save(user);
        } else {
            throw new IllegalArgumentException("user not found");
        }
    }

}
