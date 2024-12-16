package com.PigeonSkyRace.Pigeon.service;

import com.PigeonSkyRace.Pigeon.model.Season;

public interface SaisonService {
    Season getSaison(String name);
    Season addSaison(Season saison);
}
