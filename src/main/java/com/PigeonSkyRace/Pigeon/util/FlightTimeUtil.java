package com.PigeonSkyRace.Pigeon.util;

import java.time.Duration;
import java.time.LocalDateTime;

public class FlightTimeUtil {

    public static double calculateFlightTime(LocalDateTime startDate, LocalDateTime arrivalDate) {
        Duration flightTimeDuration =  Duration.between(startDate, arrivalDate);
        return formatDuration(flightTimeDuration);
    }

    public static double formatDuration(Duration duration) {
        long hours = duration.toHours();

        long minutes = duration.toMinutesPart();
        long seconds = duration.toSecondsPart();
        return hours + (minutes / 60.0) + (seconds / 3600.0);
    }

}
