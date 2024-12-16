package com.PigeonSkyRace.Pigeon.dto;

import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.UniqueElements;
import org.springframework.stereotype.Indexed;

@Getter
@Setter
public class PigeonDTO {
    private int id;

    @NotNull(message = "Name cannot be null")
    @Size(min = 2, max = 50, message = "Name must be between 2 and 50 characters")
    private String name;

    @Min(value = 0, message = "Age cannot be negative")
    @Max(value = 20, message = "Age cannot be more than 20 years")
    private int age;

    @NotNull(message = "Gender cannot be null")
    @Pattern(regexp = "^(Male|Female)$", message = "Gender must be 'Male' or 'Female'")
    private String gender;

    @NotNull(message = "Color cannot be null")
    @Size(min = 3, max = 30, message = "Color must be between 3 and 30 characters")
    private String color;

    private String badge;

    private String breederId;
}
