package com.clientRackr.api.IServices;

import com.clientRackr.api.entity.OTP;

import java.util.Optional;

public interface OTPService {
    OTP createOtp(String email);
}
