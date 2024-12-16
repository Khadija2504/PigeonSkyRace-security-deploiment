package com.PigeonSkyRace.Pigeon.service;

import com.PigeonSkyRace.Pigeon.dto.RaceData;
import com.PigeonSkyRace.Pigeon.model.Result;

import java.util.List;

public interface ResultIService {
    List<Result> getAllBreederResults(int breederId);
    List<Result> getAllResults();
    void processRaceData(int competitionId, List<RaceData> raceDataList);
    List<Result> getCompetitionResults(int competitionId);
}
