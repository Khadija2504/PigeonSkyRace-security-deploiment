package com.PigeonSkyRace.Pigeon.service.impl;

import com.PigeonSkyRace.Pigeon.model.Competition;
import com.PigeonSkyRace.Pigeon.model.Pigeon;
import com.PigeonSkyRace.Pigeon.model.Result;
import com.PigeonSkyRace.Pigeon.repository.CompetitionRepository;
import com.PigeonSkyRace.Pigeon.repository.PigeonRepository;
import com.PigeonSkyRace.Pigeon.repository.ResultRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class CompetitionServiceImpl implements com.PigeonSkyRace.Pigeon.service.CompetitionService {

    @Autowired
    private CompetitionRepository competitionRepository;
    @Autowired
    private ResultRepository resultRepository;
    @Autowired
    private PigeonRepository pigeonRepository;

    @Override
    public Competition addCompetition(Competition competition) {
        return competitionRepository.save(competition);
    }

    @Override

    public Optional<Result> updateCompetition(int id, String badge) {
        Pigeon pigeons = pigeonRepository.findByBadge(badge).getFirst();
        Optional<Competition> competitionResult = competitionRepository.findById(id);

        if (competitionResult.isPresent() && competitionResult.get().getIsOpen().equals(true)) {
            Competition competition = competitionResult.get();
            Result result = new Result();
            result.setPigeon(pigeons);
            result.setCompetition(competition);
            resultRepository.save(result);
            return Optional.of(result);
        } else {
            return Optional.empty();
        }
    }

    @Override
    public Competition getCompetitionById(int competitionId) {
        return competitionRepository.findById(competitionId).orElseThrow(() -> new IllegalArgumentException("Competition not found"));
    }

    @Override
    public Competition closeCompetition(int competitionId) {
        Competition competition = getCompetitionById(competitionId);
        if(competition.getIsOpen().equals(true)) {
            competition.setIsOpen(false);
            return competitionRepository.save(competition);
        }
        return null;
    }
}
