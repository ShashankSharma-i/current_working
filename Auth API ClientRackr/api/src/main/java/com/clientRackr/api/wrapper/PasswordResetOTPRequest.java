package com.clientRackr.api.wrapper;

import com.clientRackr.api.IValidation.MailValidator;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PasswordResetOTPRequest {

    @MailValidator
    private String email;
}
