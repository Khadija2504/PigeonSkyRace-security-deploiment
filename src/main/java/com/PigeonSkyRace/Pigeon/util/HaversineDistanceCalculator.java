package com.PigeonSkyRace.Pigeon.util;

import java.text.DecimalFormat;

public class HaversineDistanceCalculator {
    private static final double EARTH_RADIUS = 6371000;

    public static double calculateDistance(double startLat, double startLon, double endLat, double endLon) {
        double dLat = Math.toRadians(endLat - startLat);
        double dLon = Math.toRadians(endLon - startLon);

        startLat = Math.toRadians(startLat);
        endLat = Math.toRadians(endLat);

        double a = haversine(dLat) + Math.cos(startLat) * Math.cos(endLat) * haversine(dLon);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

        return Double.parseDouble(new DecimalFormat("##.##").format(EARTH_RADIUS * c));
    }

    private static double haversine(double val) {
        return Double.parseDouble(new DecimalFormat("##.##").format(Math.pow(Math.sin(val / 2), 2)));
    }
}
