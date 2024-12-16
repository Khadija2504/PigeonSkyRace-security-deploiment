package com.PigeonSkyRace.Pigeon.util;

import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.time.LocalDateTime;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class FlightTimeUtilTest {

    @Test
    public void testCalculateFlightTime() {
        LocalDateTime startDate = LocalDateTime.of(2024, 11, 13, 8, 30, 0);
        LocalDateTime arrivalDate = LocalDateTime.of(2024, 11, 13, 10, 45, 30);

        double flightTime = FlightTimeUtil.calculateFlightTime(startDate, arrivalDate);

        // Expected time: 2 h + 15 min + 30 sec => 2.2583 h (2 + 15/60 + 30/3600)
        assertEquals(2.2583, flightTime, 0.0001, "The flight time calculation did not match the expected result");
    }

    @Test
    public void testFormatDuration() {
        Duration duration = Duration.ofHours(1).plusMinutes(30).plusSeconds(45);
        double formattedDuration = FlightTimeUtil.formatDuration(duration);

        // Expected time: 1 h + 30 min + 45 sec => 1.5125 h (1 + 30/60 + 45/3600)
        assertEquals(1.5125, formattedDuration, 0.0001, "The formatted duration did not match the expected result");
    }
}
