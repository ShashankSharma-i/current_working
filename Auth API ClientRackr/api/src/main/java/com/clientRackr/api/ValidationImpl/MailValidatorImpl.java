package com.clientRackr.api.ValidationImpl;

import com.clientRackr.api.IValidation.MailValidator;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;


import java.util.regex.Pattern;

public class MailValidatorImpl implements ConstraintValidator<MailValidator, String> {


    @Override
    public void initialize(MailValidator constraintAnnotation) {
    }

    private static final String EMAIL_REGEX = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";

    @Override
    public boolean isValid(String email, ConstraintValidatorContext context) {
        if(!Pattern.matches(EMAIL_REGEX,email)){
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("error");
            return false;
        }
        return true;
    }


//    private Pattern pattern;
//
//    @Override
//    public void initialize(MailValidatorImpl constraintAnnotation) {
//        this.pattern = Pattern.compile(EMAIL_PATTERN);
//    }
//
//    @Override
//    public boolean isValid(String email, ConstraintValidatorContext context) {
//        if (email == null || email.isBlank()) {
//            return false;  // This will be handled by @NotNull and @NotBlank annotations
//        }
//
//        if (!pattern.matcher(email).matches()) {
//            context.disableDefaultConstraintViolation();
//            if (!email.contains("@")) {
//                context.buildConstraintViolationWithTemplate("Email must contain '@'")
//                        .addConstraintViolation();
//            } else if (!email.endsWith(".com") && !email.endsWith(".in")) {
//                context.buildConstraintViolationWithTemplate("Email must end with '.com' or '.in'")
//                        .addConstraintViolation();
//            } else {
//                context.buildConstraintViolationWithTemplate("Invalid email format")
//                        .addConstraintViolation();
//            }
//            return false;
//        }
//        return true;
//    }

    /*private static final String EMAIL_PATTERN = "^(?=.{1,64}@)[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*@" +
            "[^-][A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*(\\.[A-Za-z]{2,})$";
    private Pattern pattern;

    @Override
    public void initialize(MailValidatorImpl constraintAnnotation) {
        this.pattern = Pattern.compile(EMAIL_PATTERN);
    }

    @Override
    public boolean isValid(String email, ConstraintValidatorContext context) {
        if (email == null || email.isBlank()) {
            return false;  // This will be handled by @NotNull and @NotBlank annotations
        }

        if (!pattern.matcher(email).matches()) {
            // Check for specific invalid characters
            if (email.contains("@") && (email.endsWith(".com") || email.endsWith(".in"))){
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate("Email should contain '@' and end with '.com'")
                        .addConstraintViolation();
            } else {
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate("Email only contain '@' and end with '.com")
                        .addConstraintViolation();
            }
            return false;
        }
        return true;
    }*/
}

