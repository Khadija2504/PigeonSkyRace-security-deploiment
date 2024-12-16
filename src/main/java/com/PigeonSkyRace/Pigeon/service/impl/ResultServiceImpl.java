package com.PigeonSkyRace.Pigeon.service.impl;

import com.PigeonSkyRace.Pigeon.dto.RaceData;
import com.PigeonSkyRace.Pigeon.model.User;
import com.PigeonSkyRace.Pigeon.model.Competition;
import com.PigeonSkyRace.Pigeon.model.Pigeon;
import com.PigeonSkyRace.Pigeon.model.Result;
import com.PigeonSkyRace.Pigeon.repository.ResultRepository;
import com.PigeonSkyRace.Pigeon.service.UserService;
import com.PigeonSkyRace.Pigeon.service.CompetitionService;
import com.PigeonSkyRace.Pigeon.service.PigeonService;
import com.PigeonSkyRace.Pigeon.service.ResultIService;
import com.PigeonSkyRace.Pigeon.util.FlightTimeUtil;
import com.PigeonSkyRace.Pigeon.util.HaversineDistanceCalculator;
import com.PigeonSkyRace.Pigeon.util.PointsCalculator;
import com.PigeonSkyRace.Pigeon.util.SpeedCalculatorUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.text.DecimalFormat;
import java.util.*;
import java.util.function.Function;
import java.util.logging.Logger;
import java.util.stream.Collectors;

@Service
public class ResultServiceImpl implements ResultIService {

    private final Logger logger = Logger.getLogger(ResultServiceImpl.class.getName());

    @Autowired
    private ResultRepository resultRepository;

    @Autowired
    private PigeonService pigeonService;

    @Autowired
    private CompetitionService competitionService;

    @Autowired
    private UserService userService;

    @Override
    public List<Result> getAllBreederResults(int breederId) {
        Set<Integer> pigeonIds = pigeonService.getAllPigeons().stream()
                .filter(p -> Objects.equals(breederId, p.getBreeder().getId()))
                .map(Pigeon::getId)
                .collect(Collectors.toSet());
        if (pigeonIds.isEmpty()) {
            throw new IllegalArgumentException("no pigeons found for this breeder id");
        }

        return resultRepository.findAll().stream()
                .filter(result -> pigeonIds.contains(result.getPigeon().getId())).sorted(Comparator.comparingInt(Result::getRanking))
                .collect(Collectors.toList());
    }

    @Override
    public List<Result> getCompetitionResults(int competitionId) {
        return resultRepository.findAll().stream()
                .filter(result -> result.getCompetition().getId() == competitionId)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public void processRaceData(int competitionId, List<RaceData> raceDataList) {
        Competition competition = competitionService.getCompetitionById(competitionId);
        if (competition.getIsOpen()) {
            throw new IllegalArgumentException("Competition is not closed yet");
        }

        List<Pigeon> pigeons = pigeonService.getPigeonsByCompetitionId(competitionId);

        Map<String, Pigeon> pigeonMap = pigeons.stream()
                .collect(Collectors.toMap(Pigeon::getBadge, Function.identity()));

        for (RaceData raceData : raceDataList) {
            Pigeon pigeon = pigeonMap.get(raceData.getBadge());
            if (pigeon == null) {
                logger.warning("Pigeon with ring number " + raceData.getBadge() + " not found in participants. Skipping.");
                continue;
            }

            Result result = resultRepository.findByCompetitionAndPigeon(competition, pigeon);
            if (result == null) {

                result = new Result();

                result.setCompetition(competition);
                result.setPigeon(pigeon);

            }

            result.setArrivalDate(raceData.getArrivalTime());

            User breeder = userService.getBreederById(pigeon.getBreeder().getId());
            if (breeder == null) {
                logger.warning("Breeder not found for pigeon with ring number " + pigeon.getBadge());
                continue;
            }

            double distance = HaversineDistanceCalculator.calculateDistance(
                    Double.parseDouble(competition.getLatitude()), Double.parseDouble(competition.getLongitude()),
                    Double.parseDouble(breeder.getLatitude()), Double.parseDouble(breeder.getLongitude()));

            double flightTime = FlightTimeUtil.calculateFlightTime(competition.getStartDate(), raceData.getArrivalTime());

            result.setDistance(Double.parseDouble(new DecimalFormat("##.##").format(distance)));
            result.setFlightTime(flightTime);
            resultRepository.save(result);
        }

        List<Result> results = resultRepository.findByCompetitionId(competitionId);

        double averageDistance = SpeedCalculatorUtil.averageDistance(results);
        for (Result result : results) {
            double coefficient = SpeedCalculatorUtil.calculateCoefficient(result.getDistance(), averageDistance);
            double speed = SpeedCalculatorUtil.calculateSpeed(result.getFlightTime(), result.getDistance(), coefficient);
            result.setSpeed(speed);
        }

        PointsCalculator.calculatePoints(results);
        resultRepository.saveAll(results);
    }
    @Override
    public List<Result> getAllResults() {
        return resultRepository.findAll().stream().sorted(Comparator.comparingInt(Result::getRanking))
                .collect(Collectors.toList());
    }
}
