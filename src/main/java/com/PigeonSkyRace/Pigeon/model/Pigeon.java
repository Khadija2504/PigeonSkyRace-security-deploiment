package com.PigeonSkyRace.Pigeon.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.*;

@Data
@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Pigeon {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String name;

    private int age;

    private String gender;

    private String color;

    private String badge;

    @ManyToOne
    @JoinColumn(name = "breeder_id")
    private User breeder;
}
