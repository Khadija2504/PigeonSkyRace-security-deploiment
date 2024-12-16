package com.PigeonSkyRace.Pigeon.service;

import com.PigeonSkyRace.Pigeon.model.User;

import java.util.Optional;

public interface UserService {
    User createBreeder(User user);
    Optional<User> findByEmail(String email);
    User getBreederById(int userId);
    User updateUser(String email, String role);
}
