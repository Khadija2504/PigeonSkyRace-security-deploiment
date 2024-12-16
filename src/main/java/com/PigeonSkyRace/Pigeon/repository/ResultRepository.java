package com.PigeonSkyRace.Pigeon.repository;

import com.PigeonSkyRace.Pigeon.model.Competition;
import com.PigeonSkyRace.Pigeon.model.Pigeon;
import com.PigeonSkyRace.Pigeon.model.Result;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ResultRepository extends JpaRepository<Result, Integer> {
    Result findByCompetitionAndPigeon(Competition competition, Pigeon pigeon);
    List<Result> findByCompetitionId(int competitionId);
}
