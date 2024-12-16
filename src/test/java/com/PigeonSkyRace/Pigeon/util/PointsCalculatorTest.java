package com.PigeonSkyRace.Pigeon.util;

import com.PigeonSkyRace.Pigeon.model.Result;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class PointsCalculatorTest {

    @Test
    public void testCalculatePoints_ValidResults() {
        Result result1 = new Result(120.5);
        Result result2 = new Result(150.3);
        Result result3 = new Result(130.7);
        List<Result> results = Arrays.asList(result1, result2, result3);

        PointsCalculator.calculatePoints(results);

        assertEquals(1, result2.getRanking(), "The first rank should go to the highest speed");
        assertEquals(2, result3.getRanking(), "The second rank should go to the second highest speed");
        assertEquals(3, result1.getRanking(), "The third rank should go to the lowest speed");

        assertTrue(result1.getPoints() < result2.getPoints(), "The points for lower ranks should be less");
        assertTrue(result2.getPoints() > result3.getPoints(), "The points for higher ranks should be more");

        assertEquals(100, result2.getPoints(), "The highest speed should receive 100 points");
        assertEquals(50, result3.getPoints(), "The second rank should receive a reduced amount of points");
        assertEquals(0, result1.getPoints(), "The third rank should receive the lowest points");
    }

    @Test
    public void testCalculatePoints_EmptyList() {
        List<Result> results = Arrays.asList();

        PointsCalculator.calculatePoints(results);

        assertTrue(results.isEmpty(), "The result list should remain empty");
    }

    @Test
    public void testCalculatePoints_NullList() {
        List<Result> results = null;

        PointsCalculator.calculatePoints(results);

        assertNull(results, "The result list should remain null");
    }

    @Test
    public void testCalculatePoints_SingleParticipant() {
        Result result1 = new Result(120.5);
        List<Result> results = Arrays.asList(result1);

        PointsCalculator.calculatePoints(results);

        assertEquals(1, result1.getRanking(), "The only participant should be ranked 1");
        assertEquals(100, result1.getPoints(), "The only participant should receive 100 points");
    }
}
