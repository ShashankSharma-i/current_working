package com.clientRackr.api.wrapper;

import com.clientRackr.api.validators.ValidEmail;
import com.clientRackr.api.validators.ValidPassword;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ResetPasswordRequest {

    @ValidEmail
    private String email;

    @ValidPassword
    private String newPassword;

    @ValidPassword
    private String confirmPassword;

}
