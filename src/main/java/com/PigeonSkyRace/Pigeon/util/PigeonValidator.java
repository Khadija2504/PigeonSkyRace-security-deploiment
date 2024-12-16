package com.PigeonSkyRace.Pigeon.util;

import com.PigeonSkyRace.Pigeon.model.Pigeon;
import org.springframework.util.StringUtils;

public class PigeonValidator {

    public static String validatePigeonData(Pigeon pigeon) {
        if (!StringUtils.hasText(pigeon.getName())) {
            return "Name is required.";
        }

        if (pigeon.getAge() <= 0) {
            return "Age must be a positive number.";
        }

        if (!StringUtils.hasText(pigeon.getGender()) ||
                (!pigeon.getGender().equalsIgnoreCase("Male") && !pigeon.getGender().equalsIgnoreCase("Female"))) {
            return "Gender must be either 'Male' or 'Female'.";
        }

        if (!StringUtils.hasText(pigeon.getColor())) {
            return "Color is required.";
        }

        return null;
    }
}

