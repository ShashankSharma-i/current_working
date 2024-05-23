package com.clientRackr.api.wrapper;

import com.clientRackr.api.IValidation.MailValidator;
import com.clientRackr.api.IValidation.ValidFirstName;
import com.clientRackr.api.IValidation.ValidLastName;
import com.clientRackr.api.IValidation.ValidPassword;
import jakarta.persistence.Basic;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignUpRequest implements Serializable {

    @MailValidator
    private String email;

    @ValidFirstName
    @Basic
    private String firstName;

    @ValidLastName
    @Basic
    private String lastName;

    @ValidPassword
    @Basic
    private String password;

}