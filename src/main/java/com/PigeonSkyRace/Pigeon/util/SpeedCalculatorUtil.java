package com.PigeonSkyRace.Pigeon.util;

import com.PigeonSkyRace.Pigeon.model.Result;

import java.text.DecimalFormat;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class SpeedCalculatorUtil {

    public static double calculateSpeed(double flightTime, double distance, double coefficient) {
        if (flightTime == 0) {
            return 0;
        }

        double speed = distance / flightTime;

        return Double.parseDouble(new DecimalFormat("##.##").format(coefficient / speed));
    }

    public static double averageDistance (List<Result> result) {
        double averageDistance = 0;
        for (Result results: result){
            averageDistance += results.getDistance();
        }
        return Double.parseDouble(new DecimalFormat("##.##").format(averageDistance / result.size()));
    }

    public static double calculateCoefficient(double distance, double averageDistance) {
        double coefficient = 0;
        coefficient = averageDistance / distance;
        return Double.parseDouble(new DecimalFormat("##.##").format(coefficient));
    }

}
