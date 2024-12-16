package com.PigeonSkyRace.Pigeon.util;

import com.PigeonSkyRace.Pigeon.model.Result;

import java.util.Comparator;
import java.util.List;

public class PointsCalculator {

    public static void calculatePoints(List<Result> results) {
        if (results == null || results.isEmpty()) {
            return;
        }

        results.sort(Comparator.comparingDouble(Result::getSpeed).reversed());

        int totalParticipants = results.size();

        for (int i = 0; i < totalParticipants; i++) {
            Result result = results.get(i);
            int rank = i + 1;
            double points = calculatePointsForRank(rank, totalParticipants);
            result.setPoints((int) points);
            result.setRanking(rank);
        }
    }

    private static double calculatePointsForRank(int rank, int totalParticipants) {
        if (totalParticipants <= 1) {
            return 100;
        }

        return 100 * (1 - (double) (rank - 1) / (totalParticipants - 1));
    }
}
