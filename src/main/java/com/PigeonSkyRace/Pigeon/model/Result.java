package com.PigeonSkyRace.Pigeon.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Data
@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Result {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private int points;

    private double speed;

    private int ranking;

    private double distance;

    private double flightTime;

    private LocalDateTime arrivalDate;

    @ManyToOne
    @JoinColumn(name = "pigeon_id")
    private Pigeon pigeon;

    @ManyToOne
    @JoinColumn(name = "competition_id")
    private Competition competition;

    public Result(double speed) {
        this.speed = speed;
        this.points = 0;
        this.ranking = 0;
        this.distance = 0.0;
        this.flightTime = 0.0;
        this.arrivalDate = LocalDateTime.now();
    }
}
