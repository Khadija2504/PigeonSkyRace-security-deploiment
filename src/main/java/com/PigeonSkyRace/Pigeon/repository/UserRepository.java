package com.PigeonSkyRace.Pigeon.repository;

import com.PigeonSkyRace.Pigeon.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByEmail(String email);
}
