package com.PigeonSkyRace.Pigeon.repository;

import com.PigeonSkyRace.Pigeon.model.Pigeon;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PigeonRepository extends JpaRepository<Pigeon, Integer> {
    List<Pigeon> findByBadge(String badge);
}
