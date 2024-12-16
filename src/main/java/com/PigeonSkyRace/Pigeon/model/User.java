package com.PigeonSkyRace.Pigeon.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Null;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String role;
    private String name;
    private String username;

    @Null
    private String latitude;

    @Null
    private String longitude;

    private String password;
    private String email;
}
