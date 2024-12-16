package com.PigeonSkyRace.Pigeon.dto;

import com.PigeonSkyRace.Pigeon.model.enums.TypeEnum;
import jakarta.validation.constraints.FutureOrPresent;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class CompetitionDTO {
    private String id;

    @NotNull(message = "Name cannot be null")
    @Size(min = 2, max = 50, message = "Name must be between 2 and 50 characters")
    private String name;

    @NotNull(message = "Distance cannot be null")
    @Pattern(regexp = "^\\d+(\\.\\d+)?\\s?(km|m)$", message = "Distance must be in 'km' or 'm' format")
    private String distance;

    @NotNull(message = "Start date cannot be null")
    @FutureOrPresent(message = "Start date must be in the present or future")
    private LocalDateTime startDate;

    @NotNull(message = "Longitude cannot be null")
    @Pattern(regexp = "^-?\\d{1,3}\\.\\d+$", message = "Invalid longitude format")
    private String longitude;

    @NotNull(message = "Latitude cannot be null")
    @Pattern(regexp = "^-?\\d{1,2}\\.\\d+$", message = "Invalid latitude format")
    private String latitude;

    private Boolean isOpen;

    @NotNull(message = "Type cannot be null")
    private TypeEnum type;

    private int season_id;
}
