package com.clientRackr.api.IValidation;

import com.clientRackr.api.ValidationImpl.ValidFirstNameValidator;
import com.clientRackr.api.ValidationImpl.ValidLastNameValidator;
import jakarta.validation.Payload;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import javax.validation.Constraint;
import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = ValidLastNameValidator.class)
@Target({ ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER, ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidLastName {
    String message() default "Invalid last name";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
/*@Constraint(validatedBy = ValidLastNameValidator.class)
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Pattern(regexp = "^[a-zA-Z]+$", message = "Last name must contain only alphabets")
@NotNull(message = "Last name must not be null")
@NotBlank(message = "Last name must not be blank")
public @interface ValidLastName {
    String message() default "Last name must contain only alphabets";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}*/

