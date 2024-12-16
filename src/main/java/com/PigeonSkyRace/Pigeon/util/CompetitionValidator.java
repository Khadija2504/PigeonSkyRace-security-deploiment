package com.PigeonSkyRace.Pigeon.util;

import com.PigeonSkyRace.Pigeon.model.Competition;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;

public class CompetitionValidator {

    public static String validateCompetitionData(Competition competition) {
        if (!StringUtils.hasText(competition.getName())) {
            return "Competition name is required.";
        }

        if (!StringUtils.hasText(competition.getDistance()) || !competition.getDistance().matches("\\d+")) {
            return "Distance must be a positive number.";
        }

        if (competition.getStartDate() == null || competition.getStartDate().isBefore(LocalDateTime.now())) {
            return "Start date must be in the future.";
        }

        if (isValidCoordinate(competition.getLongitude())) {
            return "Invalid longitude format. Please provide a valid coordinate.";
        }

        if (isValidCoordinate(competition.getLatitude())) {
            return "Invalid latitude format. Please provide a valid coordinate.";
        }

        if (competition.getType() == null) {
            return "Competition type is required.";
        }

        return null;
    }

    private static boolean isValidCoordinate(String coordinate) {
        return coordinate == null || !coordinate.matches("-?\\d+(\\.\\d+)?");
    }
}
