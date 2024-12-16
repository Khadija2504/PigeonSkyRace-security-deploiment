package com.PigeonSkyRace.Pigeon.dto;

import lombok.Getter;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

@Getter
public class RaceData {

    private String badge;
    private LocalDateTime arrivalTime;

    public RaceData(String ringNumber, String arrivalTimeString) {
        this.badge = ringNumber.trim().replace("\u0000", "");

        try {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            this.arrivalTime = LocalDateTime.parse(arrivalTimeString.trim().replace("\u0000", ""), formatter);
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("Invalid arrival time format: " + arrivalTimeString);
        }
    }

}
