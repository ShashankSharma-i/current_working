package com.clientRackr.api.wrapper;

import com.clientRackr.api.IValidation.MailValidator;
import com.clientRackr.api.IValidation.ValidPassword;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ResetPasswordRequest {

    @MailValidator
    private String email;

    @ValidPassword
    private String newPassword;

    @ValidPassword
    private String confirmPassword;

    private Integer OTP;


}
