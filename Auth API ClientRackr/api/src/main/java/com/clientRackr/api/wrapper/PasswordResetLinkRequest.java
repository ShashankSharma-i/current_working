package com.clientRackr.api.wrapper;

import com.clientRackr.api.validators.ValidEmail;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PasswordResetLinkRequest {

    @ValidEmail
    private String email;
}
