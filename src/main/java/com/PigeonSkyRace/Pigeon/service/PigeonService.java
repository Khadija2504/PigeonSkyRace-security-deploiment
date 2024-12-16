package com.PigeonSkyRace.Pigeon.service;

import com.PigeonSkyRace.Pigeon.model.Competition;
import com.PigeonSkyRace.Pigeon.model.Pigeon;

import java.util.List;

public interface PigeonService {
    Pigeon addPigeon(Pigeon pigeon);
    List<Pigeon> getAllPigeons();
    List<Pigeon> getPigeonsByCompetitionId(int competitionId);
}
