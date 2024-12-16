package com.PigeonSkyRace.Pigeon.dto;

import com.PigeonSkyRace.Pigeon.model.Competition;
import jakarta.validation.constraints.FutureOrPresent;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class SeasonDTO {
    private int id;
    @NotNull(message = "Name cannot be null")
    private String name;
    @NotNull(message = "Date cannot be null")
    @FutureOrPresent(message = "Date must be in the present or future")
    private LocalDateTime date;

    private Competition competition;
}
