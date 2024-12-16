package com.PigeonSkyRace.Pigeon.dto;

import com.PigeonSkyRace.Pigeon.model.Pigeon;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class UserDTO {
    private String id;

    @NotNull(message = "Name cannot be null")
    @Size(min = 3, max = 50, message = "Name must be between 3 and 50 characters")
    private String name;

    @Null
    @Pattern(regexp = "^-?\\d{1,2}\\.\\d+$", message = "Invalid latitude format")
    private String latitude;

    @Null
    @Pattern(regexp = "^-?\\d{1,3}\\.\\d+$", message = "Invalid longitude format")
    private String longitude;

    @NotNull(message = "Password cannot be null")
    @Size(min = 6, message = "Password must be at least 6 characters long")
    private String password;

    @NotNull(message = "Email cannot be null")
    @Email(message = "Email should be valid")
    private String email;

    @Pattern(regexp = "^(breeder|organizer)$", message = "role must be organizer or breeder")
    private String role;

    private List<Pigeon> pigeons;
}
