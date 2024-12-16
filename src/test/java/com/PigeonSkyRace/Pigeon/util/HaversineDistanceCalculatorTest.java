package com.PigeonSkyRace.Pigeon.util;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class HaversineDistanceCalculatorTest {

    @Test
    public void testCalculateDistance_SamePoint() {
        double distance = HaversineDistanceCalculator.calculateDistance(40.7128, -74.0060, 40.7128, -74.0060);
        assertEquals(0.0, distance, 0.001, "Distance between the same points should be 0.");
    }

    @Test
    public void testCalculateDistance_KnownDistance() {
        double distance = HaversineDistanceCalculator.calculateDistance(40.7128, -74.0060, 34.0522, -118.2437);
        assertEquals(3944000, distance, 10000, "Distance between New York and Los Angeles should be approximately 3944 km.");
    }

    @Test
    public void testCalculateDistance_ShortDistance() {
        double distance = HaversineDistanceCalculator.calculateDistance(48.8566, 2.3522, 48.8584, 2.2945);
        assertEquals(4300, distance, 100, "Distance between two points in Paris should be approximately 4.3 km.");
    }
}
