package com.clientRackr.api.ValidationImpl;
import com.clientRackr.api.IValidation.ValidPassword;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.regex.Pattern;

public class ValidPasswordValidator implements ConstraintValidator<ValidPassword, String> {

    private static final String PASSWORD_PATTERN =
            "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,20}$";
    private Pattern pattern;

    @Override
    public void initialize(ValidPassword constraintAnnotation) {
        this.pattern = Pattern.compile(PASSWORD_PATTERN);
    }

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {

        if (password == null || password.isBlank()) {
            return false;  // This will be handled by @NotNull and @NotBlank annotations
        }

        if (!pattern.matcher(password).matches()) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(
                    "Password must be 8-20 characters long and contain at least one digit, " +
                            "one lowercase letter, one uppercase letter, one special character, " +
                            "and no whitespace."
            ).addConstraintViolation();
            return false;
        }
        return true;
    }
}

/*import com.clientRackr.api.IValidation.ValidPassword;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.regex.Pattern;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.regex.Pattern;

public class ValidPasswordValidator implements ConstraintValidator<ValidPassword, String> {

    private static final String PASSWORD_PATTERN = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,20}$";
    private Pattern pattern;

    @Override
    public void initialize(ValidPassword constraintAnnotation) {
        this.pattern = Pattern.compile(PASSWORD_PATTERN);
    }

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null || password.isBlank()) {
            return false;  // This will be handled by @NotNull and @NotBlank annotations
        }

        if (!pattern.matcher(password).matches()) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("Password must contain at least one digit, one lowercase letter, one uppercase letter, one special character, and be 8-20 characters long")
                    .addConstraintViolation();
            return false;
        }
        return true;
    }
}*/


