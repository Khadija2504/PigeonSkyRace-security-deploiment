package com.PigeonSkyRace.Pigeon.util;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class PasswordUtilTest {

    @Test
    public void testHashPassword_Success() {
        String password = "mySecurePassword";

        String hashedPassword = PasswordUtil.hashPassword(password);

        assertNotNull(hashedPassword, "Hashed password should not be null");
        assertNotEquals(password, hashedPassword, "Hashed password should not be equal to original password");
        assertEquals(64, hashedPassword.length(), "Hashed password length should be 64 characters (SHA-256)");
    }

    @Test
    public void testHashPassword_DifferentPasswords() {
        String password1 = "password1";
        String password2 = "password2";

        String hashedPassword1 = PasswordUtil.hashPassword(password1);
        String hashedPassword2 = PasswordUtil.hashPassword(password2);

        assertNotEquals(hashedPassword1, hashedPassword2, "Hashed passwords for different inputs should be different");
    }

    @Test
    public void testHashPassword_EmptyPassword() {
        String password = "";

        String hashedPassword = PasswordUtil.hashPassword(password);

        assertNotNull(hashedPassword, "Hashed password should not be null");
        assertEquals(64, hashedPassword.length(), "Hashed password length should be 64 characters for empty string");
    }

    @Test
    public void testHashPassword_NullPassword() {
        String password = null;

        assertThrows(NullPointerException.class, () -> {
            PasswordUtil.hashPassword(password);
        }, "Expected to throw NullPointerException for null password");
    }
}
