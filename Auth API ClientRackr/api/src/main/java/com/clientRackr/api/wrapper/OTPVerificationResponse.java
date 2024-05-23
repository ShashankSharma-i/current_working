package com.clientRackr.api.wrapper;

import com.clientRackr.api.IValidation.MailValidator;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OTPVerificationResponse {

    @MailValidator
    private String email;
    private String message;

}
