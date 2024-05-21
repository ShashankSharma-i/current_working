package com.clientRackr.api.validators;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = {})
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Pattern(regexp = "^[a-zA-Z]+$", message = "First name must contain only alphabets")
@NotNull(message = "First name must not be null")
@NotBlank(message = "First name must not be blank")
public @interface ValidFirstName {
    String message() default "First name must contain only alphabets";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
