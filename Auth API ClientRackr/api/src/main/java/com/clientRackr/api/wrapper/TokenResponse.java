package com.clientRackr.api.wrapper;

import com.clientRackr.api.validators.ValidEmail;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenResponse {

    @ValidEmail
    private String email;
    private String token;
}
