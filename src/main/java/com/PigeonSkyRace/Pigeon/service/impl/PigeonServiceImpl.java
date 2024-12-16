package com.PigeonSkyRace.Pigeon.service.impl;

import com.PigeonSkyRace.Pigeon.service.PigeonService;
import com.PigeonSkyRace.Pigeon.model.Pigeon;
import com.PigeonSkyRace.Pigeon.model.Result;
import com.PigeonSkyRace.Pigeon.repository.PigeonRepository;
import com.PigeonSkyRace.Pigeon.repository.ResultRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.stream.Collectors;

@Service
public class PigeonServiceImpl implements PigeonService {

    @Autowired
    private PigeonRepository pigeonRepository;

    @Autowired
    private ResultRepository resultRepository;

    @Override
    public Pigeon addPigeon(Pigeon pigeon) {
        int uniqueNumber = generateUniqueNumber();
        String gender = Objects.equals(pigeon.getGender(), "Male") ? "M" : "F";

        String badge = gender + uniqueNumber + "-" + pigeon.getAge();
        pigeon.setBadge(badge);
        return pigeonRepository.save(pigeon);
    }

    private int generateUniqueNumber() {
        Random random = new Random();
        return 10000 + random.nextInt(90000);
    }

    @Override
    public List<Pigeon> getAllPigeons(){
        return pigeonRepository.findAll();
    }

    @Override
    public List<Pigeon> getPigeonsByCompetitionId(int competitionId) {
        List<Result> results = resultRepository.findByCompetitionId(competitionId);
        return results.stream()
                .map(Result::getPigeon)
                .collect(Collectors.toList());
    }
}
