package com.clientRackr.api.ValidationImpl;

import com.clientRackr.api.IValidation.ValidLastName;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.regex.Pattern;

public class ValidLastNameValidator implements ConstraintValidator<ValidLastName, String> {

    @Override
    public void initialize(ValidLastName constraintAnnotation) {
    }

    @Override
    public boolean isValid(String lastName, ConstraintValidatorContext context) {
        if (lastName == null) {
            return false;
        }
        // Example: Last name must be non-null and only contain letters
        return lastName.matches("^[a-zA-Z]+$");
    }
/*
    private static final String NAME_PATTERN = "^[a-zA-Z]+$";
    private Pattern pattern;

    @Override
    public void initialize(ValidLastName constraintAnnotation) {
        this.pattern = Pattern.compile(NAME_PATTERN);
    }

    @Override
    public boolean isValid(String lastName, ConstraintValidatorContext context) {
        if (lastName == null || lastName.isBlank()) {
            return false;  // This will be handled by @NotNull and @NotBlank annotations
        }

        if (!pattern.matcher(lastName).matches()) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("Last name must contain only alphabets")
                    .addConstraintViolation();
            return false;
        }
        return true;
    }*/
}

