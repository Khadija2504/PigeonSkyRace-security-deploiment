package com.PigeonSkyRace.Pigeon.controller;

import com.PigeonSkyRace.Pigeon.dto.AuthRequest;
import com.PigeonSkyRace.Pigeon.dto.UserDTO;
import com.PigeonSkyRace.Pigeon.mapper.UserMapper;
import com.PigeonSkyRace.Pigeon.model.User;
import com.PigeonSkyRace.Pigeon.service.UserService;
import com.PigeonSkyRace.Pigeon.util.PasswordUtil;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final Logger logger = Logger.getLogger(AuthController.class.getName());

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration.time}")
    private long jwtExpirationTime;

    @Autowired
    private UserService userService;
    @Autowired
    private UserMapper userMapper;

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody UserDTO breederDTO) {
        User breeder = userMapper.toEntity(breederDTO);
        breeder.setRole("breeder");
        User createdBreeder = userService.createBreeder(breeder);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdBreeder);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest) {
        Optional<User> optionalUser = userService.findByEmail(authRequest.getEmail());

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            if (PasswordUtil.hashPassword(authRequest.getPassword()).equals(user.getPassword())) {
                logger.info("User authenticated successfully: " + user.getEmail() + " and " + user.getId() + user.getRole());

                String token = JWT.create()
                        .withClaim("userId", user.getId())
                        .withClaim("role", user.getRole())
                        .sign(Algorithm.HMAC512(jwtSecret));

                return ResponseEntity.ok(Map.of("token", token));
            }
        }
        logger.warning("Unauthorized login attempt for email: " + authRequest.getEmail());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid email or password");
    }
}
