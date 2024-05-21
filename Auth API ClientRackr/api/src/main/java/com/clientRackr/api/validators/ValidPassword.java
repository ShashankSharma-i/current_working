package com.clientRackr.api.validators;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = {})
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,20}$", message = "Password must contain at least one digit, one lowercase letter, one uppercase letter, one special character, and be 8-20 characters long")
@NotNull(message = "Password must not be null")
public @interface ValidPassword {
    String message() default "Password must contain at least one digit, one lowercase letter, one uppercase letter, one special character, and be 8-20 characters long";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
