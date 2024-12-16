package com.PigeonSkyRace.Pigeon.dto;

import com.PigeonSkyRace.Pigeon.model.Competition;
import com.PigeonSkyRace.Pigeon.model.Pigeon;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class ResultDTO {
    private String id;

    private int points;

    private double speed;

    private int ranking;

    private double distance;

    private double flightTime;

    @NotNull(message = "Arrival date cannot be null")
    private LocalDateTime arrivalDate;

    private int pigeon_id;

    private Competition competition;

}
