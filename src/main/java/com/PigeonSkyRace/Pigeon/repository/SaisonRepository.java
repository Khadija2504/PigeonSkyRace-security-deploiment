package com.PigeonSkyRace.Pigeon.repository;

import com.PigeonSkyRace.Pigeon.model.Season;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SaisonRepository extends JpaRepository<Season, Integer> {
    Season findSaisonByName(String saisonName);
}
