package com.clientRackr.api.wrapper;

import com.clientRackr.api.validators.ValidEmail;
import com.clientRackr.api.validators.ValidFirstName;
import com.clientRackr.api.validators.ValidLastName;
import com.clientRackr.api.validators.ValidPassword;
import jakarta.persistence.Basic;
import jakarta.persistence.Column;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignUpRequest {
    @ValidEmail
    @Column(unique = true)
    @Basic
    private String email;

    @ValidPassword
    @Basic
    private String password;

    @ValidFirstName
    @Basic
    private String firstName;

    @ValidLastName
    @Basic
    private String lastName;

    @Basic
    private Integer OTP;
}