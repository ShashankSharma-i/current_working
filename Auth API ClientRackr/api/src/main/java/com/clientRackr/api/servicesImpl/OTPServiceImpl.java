package com.clientRackr.api.servicesImpl;

import com.clientRackr.api.IServices.OTPService;
import com.clientRackr.api.entity.OTP;
import com.clientRackr.api.repository.OtpRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Random;

@Service
public class OTPServiceImpl implements OTPService {

    @Autowired
    private OtpRepository otpRepository;

    public String generateOtp() {
        Random random = new Random();
        return String.format("%06d", random.nextInt(100000,999999));
    }

    public OTP createOtp(String email) {
        Integer otp = Integer.parseInt(generateOtp());
        LocalDateTime now = LocalDateTime.now();
        OTP otpEntity = OTP.builder().email(email).oneTimePassword(otp).otpTimestamp(now).build();
        return otpEntity;
    }


}
