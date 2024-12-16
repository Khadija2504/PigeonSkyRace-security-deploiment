package com.PigeonSkyRace.Pigeon.controller;

import com.PigeonSkyRace.Pigeon.model.User;
import com.PigeonSkyRace.Pigeon.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
public class AdminController {
    @Autowired
    private UserService userService;

    @PostMapping("/switchRoles")
    public ResponseEntity<?> updateUserRole(@RequestParam String email, String role) {
        System.out.println(email);
        String currentUserRole = SecurityContextHolder.getContext().getAuthentication().getAuthorities().toString();
        System.out.println("Current User Role: " + currentUserRole);
        try {
            User updatedUser = userService.updateUser(email, role);
            return ResponseEntity.status(HttpStatus.CREATED).body(updatedUser);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }
}
