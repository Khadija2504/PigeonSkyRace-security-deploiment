package com.PigeonSkyRace.Pigeon.util;

import com.PigeonSkyRace.Pigeon.model.Result;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class SpeedCalculatorUtilTest {

    @Test
    public void testCalculateSpeed_ValidInputs() {
        double flightTime = 10.0;
        double distance = 100.0;
        double coefficient = 2.0;

        double result = SpeedCalculatorUtil.calculateSpeed(flightTime, distance, coefficient);

        assertEquals(0.2, result, 0.0001, "Speed calculation should return the correct value");
    }

    @Test
    public void testCalculateSpeed_FlightTimeZero() {
        double flightTime = 0.0;
        double distance = 100.0;
        double coefficient = 2.0;

        double result = SpeedCalculatorUtil.calculateSpeed(flightTime, distance, coefficient);

        assertEquals(0, result, "Speed should be 0 when flightTime is 0");
    }

    @Test
    public void testCalculateCoefficient_ValidInputs() {
        double distance = 100.0;
        double averageDistance = 150.0;

        double coefficient = SpeedCalculatorUtil.calculateCoefficient(distance, averageDistance);

        assertEquals(1.5, coefficient, "The coefficient should be calculated correctly");
    }
}
