package com.clientRackr.api.IValidation;

import com.clientRackr.api.ValidationImpl.ValidFirstNameValidator;
import jakarta.validation.Payload;

import javax.validation.Constraint;
import java.lang.annotation.*;


@Documented
@Constraint(validatedBy = ValidFirstNameValidator.class)
@Target({ ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER, ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidFirstName {
    String message() default "Invalid first name";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
/*
@Constraint(validatedBy = ValidFirstNameValidator.class)
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
*/

