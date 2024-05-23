package com.clientRackr.api.IServices;

import com.clientRackr.api.entity.OTP;
import com.clientRackr.api.wrapper.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;

public interface AuthService {
    ResponseEntity registerUser(SignUpRequest signUpRequest);

    ResponseEntity<LogInResponse> login(LogInRequest logInRequest, HttpServletRequest request);

    ResponseEntity<ResetPasswordResponse> resetPassword(ResetPasswordRequest resetPasswordRequest, HttpServletRequest request);

    OTP saveOtp(String email);

    ResponseEntity<String> resendOTP(String email);

    ResponseEntity<OTPVerificationResponse> verifyOTP(String email, Integer OTP);

    //ResponseEntity<ResetPasswordResponse> PasswordResetOTP(PasswordResetOTPRequest passwordResetOTPRequest);
}
