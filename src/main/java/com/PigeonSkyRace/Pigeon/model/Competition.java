package com.PigeonSkyRace.Pigeon.model;

import com.PigeonSkyRace.Pigeon.model.enums.TypeEnum;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Data
@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Competition {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String name;

    private String distance;

    private LocalDateTime startDate;

    private String longitude;

    private String latitude;

    private Boolean isOpen;

    private TypeEnum type;

    @ManyToOne
    @JoinColumn(name = "season_id")
    private Season season;
}
