package com.clientRackr.api.servicesImpl;

import com.clientRackr.api.CTConstant.CTConstant;
import com.clientRackr.api.IServices.AuthService;
import com.clientRackr.api.IServices.OTPService;
import com.clientRackr.api.auth.JwtUtil;
import com.clientRackr.api.entity.OTP;
import com.clientRackr.api.entity.User;
import com.clientRackr.api.repository.OtpRepository;
import com.clientRackr.api.repository.UserRepository;
import com.clientRackr.api.wrapper.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.mail.internet.MimeMessage;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;

@Service
public class AuthServiceImpl implements AuthService {

    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);
    private final JwtUtil jwtUtil;
    BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

    @Autowired
    OTPService otpService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JavaMailSender javaMailSender;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private OtpRepository otpRepository;
    @Autowired
    private TemplateEngine templateEngine;


    @Autowired
    public AuthServiceImpl(UserRepository userRepository, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }


    @Override
    public ResponseEntity<SignUpResponse> registerUser(SignUpRequest signUpRequest) {
        logger.info("Entering AuthServiceImpl :: registerUser method...");
        Boolean isVerified = false;
        String message = null;
        try {
            ValidationResponse validationResult = validateSignUpRequest(signUpRequest);
            if (!validationResult.isValid()) {
                message = validateSignUpRequest(signUpRequest).getMessage();
                logger.warn(message);
                return new ResponseEntity<>(SignUpResponse.builder().message(message).build(), HttpStatus.BAD_REQUEST);
            }

            String email = signUpRequest.getEmail();

           /* if (email == null || email.isEmpty()) {
                logger.warn("Email is null or empty");
                return new ResponseEntity<>(
                        SignUpResponse.builder()
                                .message("Email is required")
                                .build(),
                        HttpStatus.BAD_REQUEST
                );
            }*/
 /*           if (otp == null) {
                logger.warn("OTP is null");
                return new ResponseEntity<>(
                        SignUpResponse.builder()
                                .email(email)
                                .message("OTP is required")
                                .build(),
                        HttpStatus.BAD_REQUEST
                );
            }*/

/*            OTP existingOTP = otpRepository.findByEmail(email);
            if (existingOTP == null) {
                logger.warn("No OTP found for email: {}", email);
                return new ResponseEntity<>(
                        SignUpResponse.builder()
                                .email(email)
                                .message("Invalid OTP")
                                .build(),
                        HttpStatus.UNAUTHORIZED
                );
            }*/

            String signUpRequestJson = objectMapper.writeValueAsString(signUpRequest);
            logger.info("SignUpRequest: {}", signUpRequestJson);

/*            if (!isValidSignUpRequest(signUpRequest)) {
                logger.warn("Invalid sign-up request");
                return new ResponseEntity<>(
                        SignUpResponse.builder()
                                .message("Invalid sign-up request")
                                .build(),
                        HttpStatus.BAD_REQUEST
                );
            }*/

            Optional<User> existingUser = userRepository.findByEmail(email);
            if (existingUser.isPresent()) {
                logger.error("User already exists");
                return new ResponseEntity<>(SignUpResponse.builder().email(email).message("User already exists").build(), HttpStatus.BAD_REQUEST);
            }

           /* if (!isValidEmail(email) || !isValidPassword(signUpRequest.getPassword())) {
                logger.error("Invalid email or password");
                return new ResponseEntity<>(
                        SignUpResponse.builder()
                                .message("Invalid email or password")
                                .build(),
                        HttpStatus.BAD_REQUEST
                );
            }*/

            /*LocalDateTime creationTime = existingOTP.getOtpTimestamp();
            LocalDateTime currentTime = LocalDateTime.now();
            Duration duration = Duration.between(creationTime, currentTime);
            if (duration.toMinutes() > 5) {
                logger.warn("OTP expired for email: {}", email);
                return new ResponseEntity<>(
                        SignUpResponse.builder()
                                .email(email)
                                .message("Invalid OTP")
                                .build(),
                        HttpStatus.UNAUTHORIZED
                );
            }*/

            // need to send the otp mail to the user's email and save it to OTP repo
           saveOtp(email);

            User user = new User();
            user.setEmail(email);
            user.setFirstName(signUpRequest.getFirstName());
            user.setLastName(signUpRequest.getLastName());
            user.setPassword(bCryptPasswordEncoder.encode(signUpRequest.getPassword()));
            user.setIsVerified(isVerified); // isVerified = false, till the user isn't verified
            userRepository.save(user);

            logger.info("User saved successfully");
            return new ResponseEntity<>(SignUpResponse.builder().email(email).message("User saved successfully, verify the OTP").build(), HttpStatus.CREATED);
        } catch (Exception e) {
            logger.error(message, e);
            return new ResponseEntity<>(SignUpResponse.builder().message(message).build(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @Override
    public ResponseEntity<LogInResponse> login(LogInRequest logInRequest, HttpServletRequest request) {

        logger.info("Entering AuthServiceImpl :: login method...");
        try {
            if (isValidLogInRequest(logInRequest)) {
                LogInResponse response = null;

                logger.debug("inside the if block of login method..");
                String userEmail = logInRequest.getEmail();
                String userPassword = logInRequest.getPassword();

                User existingUser = userRepository.findByEmail(userEmail).orElseThrow(() -> new EntityNotFoundException("User not found"));
                String existingUserPassword = existingUser.getPassword();
                Boolean flag = existingUser.getIsVerified();
                logger.info("Authenticating user...");
                this.doAuthenticate(userEmail, userPassword);
                UserDetails userDetails = userDetailsService.loadUserByUsername(logInRequest.getEmail());

                if (userPassword != null && bCryptPasswordEncoder.matches(userPassword, existingUserPassword) && flag) {
                    String token = jwtUtil.createToken(logInRequest);

                    response = LogInResponse.builder().message("Successfully logged in").email(userDetails.getUsername()).token(token).build();

                    logger.info("User logged in successfully.");

                    return new ResponseEntity<>(response, HttpStatus.OK);
                } else {

                    response = LogInResponse.builder().message("OTP Verification Needed Before Login").email(userDetails.getUsername()).build();

                    return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
                }
            }
        } catch (EntityNotFoundException e) {
            logger.error("User not found", e);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(LogInResponse.builder().email(logInRequest.getEmail()).message("Invalid email or password").build());
        } catch (Exception e) {
            logger.error("An error occurred", e);
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        logger.info("AuthServiceImpl :: login method end...");
        return null;
    }

//reset password old api by sachin sir
   /* @Override
    public ResponseEntity<ResetPasswordResponse> resetPassword(ResetPasswordRequest resetPasswordRequest, HttpServletRequest request) {
        String newPassword = resetPasswordRequest.getNewPassword();
        String confirmPassword = resetPasswordRequest.getConfirmPassword();
        String email = resetPasswordRequest.getEmail();
        User existUser = userRepository.findByEmail(email).get();
        Boolean validatorResponse = validateParameters(email, newPassword, confirmPassword);
        if (existUser.getPassword() != null && validatorResponse) {
            if (!bCryptPasswordEncoder.matches(newPassword, existUser.getPassword())) {
                if (newPassword.equals(confirmPassword)) {
                    String encodedPassword = bCryptPasswordEncoder.encode(newPassword);
                    existUser.setPassword(encodedPassword);
                    userRepository.save(existUser);
                    return ResponseEntity.status(HttpStatus.OK)
                            .body(new ResetPasswordResponse(resetPasswordRequest.getEmail(), "Password Updated Sucessfully"));

                } else {
                    return new ResponseEntity("you confirm password are not same as new password", HttpStatus.BAD_REQUEST);
                }
            } else {
                return new ResponseEntity("you new password should not be same as old password", HttpStatus.BAD_REQUEST);
            }
        } else {
            return new ResponseEntity("Password should not be null or should be strong", HttpStatus.BAD_REQUEST);
        }
    }*/

    //reset password old api by me
    @Override
    public ResponseEntity<ResetPasswordResponse> resetPassword(ResetPasswordRequest resetPasswordRequest, HttpServletRequest request) {
        logger.info("Entering AuthServiceImpl :: resetPassword method...");

        if (resetPasswordRequest == null) {
            logger.error("ResetPasswordRequest is null");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ResetPasswordResponse(null, "Request body is null"));
        }

        if (isNullOrEmpty(resetPasswordRequest.getNewPassword()) || "null".equals(resetPasswordRequest.getNewPassword())) {
            logger.error("New password is null or empty");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ResetPasswordResponse(resetPasswordRequest.getEmail(), "New password is required"));
        }

        if (isNullOrEmpty(resetPasswordRequest.getConfirmPassword()) || "null".equals(resetPasswordRequest.getConfirmPassword())) {
            logger.error("Confirm password is null or empty");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ResetPasswordResponse(resetPasswordRequest.getEmail(), "Confirm password is required"));
        }

        if (isNullOrEmpty(resetPasswordRequest.getEmail()) || "null".equals(resetPasswordRequest.getEmail())) {
            logger.error("Email is null or empty");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ResetPasswordResponse(null, "Email is required"));
        }

        if (resetPasswordRequest.getOTP() == null && !resetPasswordRequest.getNewPassword().equals(0)) {
            logger.error("OTP is null");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ResetPasswordResponse(resetPasswordRequest.getEmail(), "OTP is required"));
        }

        if (resetPasswordRequest.getOTP() == 0) {
            logger.error("OTP cannot be zero");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ResetPasswordResponse(resetPasswordRequest.getEmail(), "OTP cannot be zero"));
        }

        String newPassword = resetPasswordRequest.getNewPassword();
        String confirmPassword = resetPasswordRequest.getConfirmPassword();
        String email = resetPasswordRequest.getEmail();
        Integer otpValue = resetPasswordRequest.getOTP();

        try {
            OTP otp = otpRepository.findByEmail(email);
            Integer existingOTP = otp.getOneTimePassword();
            LocalDateTime existingOTPTime = otp.getOtpTimestamp();

            User existUser = userRepository.findByEmail(email)
                    .orElseThrow(() -> new EntityNotFoundException("User not found"));

            if (existUser.getIsVerified() == null || !existUser.getIsVerified()) {
                logger.error("User must be verified");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ResetPasswordResponse(email, "User must be verified"));
            }

            boolean validatorResponse = validateParameters(email, newPassword, confirmPassword);
            if (!validatorResponse) {
                logger.error("Invalid parameters for password reset");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ResetPasswordResponse(email, "Invalid parameters for password reset"));
            }

            if (existingOTP.equals(otpValue) &&
                    existingOTPTime.isBefore(LocalDateTime.now()) &&
                    existingOTPTime.plusMinutes(5).isAfter(LocalDateTime.now())) {

                if (!bCryptPasswordEncoder.matches(newPassword, existUser.getPassword())) {
                    if (newPassword.equals(confirmPassword)) {
                        String encodedPassword = bCryptPasswordEncoder.encode(newPassword);
                        existUser.setPassword(encodedPassword);
                        userRepository.save(existUser);

                        logger.info("Password updated successfully for user: {}", email);
                        return ResponseEntity.status(HttpStatus.OK)
                                .body(new ResetPasswordResponse(email, "Password updated successfully"));
                    } else {
                        logger.error("New password and confirm password do not match");
                        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ResetPasswordResponse(email, "Confirm password does not match new password"));
                    }
                } else {
                    logger.error("New password should not be the same as the old password");
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(new ResetPasswordResponse(email, "New password should not be the same as the old password"));
                }
            } else {
                logger.error("OTP is invalid or expired");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ResetPasswordResponse(email, "OTP is invalid or expired"));
            }
        } catch (EntityNotFoundException e) {
            logger.error("Entity not found: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ResetPasswordResponse(email, e.getMessage()));
        } catch (Exception e) {
            logger.error("An error occurred: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResetPasswordResponse(email, "An internal error occurred"));
        } finally {
            logger.info("AuthServiceImpl :: resetPassword method end...");
        }
    }

    private boolean isNullOrEmpty(String str) {
        return str == null || str.trim().isEmpty();
    }


    @Override
    public OTP saveOtp(String email) {
        OTP otpEntity = otpService.createOtp(email);
        Integer otp = otpEntity.getOneTimePassword();
        String message = CTConstant.OTP_MAIL_MESSAGE_FORMAT + otp;
        sendingEmail(message, CTConstant.ACCOUNT_REGISTRATION_EMAIL_SUBJECT, email);
        otpRepository.save(otpEntity);
        return otpEntity;
    }


    @Override
    public ResponseEntity<String> resendOTP(String email) {
        try {
            OTP otp = otpRepository.findByEmail(email);
            if (otp != null) {
                if (otp.getOneTimePassword() != null && !otp.getOneTimePassword().equals("")) {
                    otp.setOneTimePassword(null);
                    Random random = new Random();
                    Integer newOtp = random.nextInt(10000, 99999);

                    String message = String.format(CTConstant.RESEND_OTP_MAIL_MESSAGE, newOtp);
                    sendingEmail(message, CTConstant.RESEND_OTP_MAIL_SUBJECT, email);
                    otp.setOneTimePassword(newOtp);
                    otp.setOtpTimestamp(LocalDateTime.now());
                    otpRepository.save(otp);
                    return new ResponseEntity<String>("OTP will resend to the email " + email, HttpStatus.OK);
                } else {
                    return new ResponseEntity<String>(HttpStatus.BAD_REQUEST);
                }
            } else {
                return new ResponseEntity<String>(HttpStatus.BAD_REQUEST);
            }
        } catch (Exception e) {
            logger.error(e.toString());
            return new ResponseEntity<String>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

/*
    @Override
    public ResponseEntity<OTPVerificationResponse> verifyOTP(String email, Integer OTP) {
        try {
            OTP otp = otpRepository.findByEmail(email);
            Long otpId = otp.getId();
            Integer oneTimePassword = otp.getOneTimePassword();
            LocalDateTime otpTime = otp.getOtpTimestamp();
            if (oneTimePassword.equals(OTP) && (otpTime.isBefore(LocalDateTime.now().withSecond(0).withNano(0)) && (otpTime.plusMinutes(5).isAfter(LocalDateTime.now().withSecond(0).withNano(0))))) {
                User user = userRepository.findByEmail(email).get();
                user.setIsVerified(true);
                userRepository.save(user);
                otpRepository.deleteById(otpId);
                return new ResponseEntity<>(OTPVerificationResponse.builder().email(email).message("OTP Verified Sucessfully").build(), HttpStatus.OK);
            } else {
                return new ResponseEntity<>(OTPVerificationResponse.builder().email(email).message("Invalid OTP").build(), HttpStatus.BAD_REQUEST);
            }
        } catch (Exception e) {
            logger.error(e.toString());
            return new ResponseEntity<>(OTPVerificationResponse.builder().email(email).message(e.toString()).build(), HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }*/
@Override
public ResponseEntity<OTPVerificationResponse> verifyOTP(String email, Integer otpInput) {
    try {
        // Fetch the OTP record for the given email
        OTP otp = otpRepository.findByEmail(email);

        if (otp == null) {
            return new ResponseEntity<>(OTPVerificationResponse.builder()
                    .email(email)
                    .message("OTP not found")
                    .build(), HttpStatus.NOT_FOUND);
        }

        Integer storedOtp = otp.getOneTimePassword();
        LocalDateTime otpTimestamp = otp.getOtpTimestamp();
        LocalDateTime now = LocalDateTime.now().withSecond(0).withNano(0);

        // Check if the provided OTP matches the stored OTP and is within the valid time window
        if (storedOtp.equals(otpInput) && isOtpValid(otpTimestamp, now)) {
            // Verify the user
            Optional<User> userOptional = userRepository.findByEmail(email);
            if (userOptional.isPresent()) {
                User user = userOptional.get();
                user.setIsVerified(true);
                userRepository.save(user);
                otpRepository.deleteById(otp.getId());
                return new ResponseEntity<>(OTPVerificationResponse.builder()
                        .email(email)
                        .message("OTP Verified Successfully")
                        .build(), HttpStatus.OK);
            } else {
                return new ResponseEntity<>(OTPVerificationResponse.builder()
                        .email(email)
                        .message("User not found")
                        .build(), HttpStatus.NOT_FOUND);
            }
        } else {
            return new ResponseEntity<>(OTPVerificationResponse.builder()
                    .email(email)
                    .message("Invalid OTP")
                    .build(), HttpStatus.BAD_REQUEST);
        }
    } catch (Exception e) {
        logger.error("Error verifying OTP for email {}: {}", email, e.toString());
        return new ResponseEntity<>(OTPVerificationResponse.builder()
                .email(email)
                .message("Internal server error")
                .build(), HttpStatus.INTERNAL_SERVER_ERROR);
    }
}

    private boolean isOtpValid(LocalDateTime otpTimestamp, LocalDateTime now) {
        return otpTimestamp.isBefore(now) && otpTimestamp.plusMinutes(5).isAfter(now);
    }


    /*@Override
    public ResponseEntity<ResetPasswordResponse> PasswordResetOTP(PasswordResetOTPRequest passwordResetOTPRequest) {
        String email = passwordResetOTPRequest.getEmail();
        try {
            User user = userRepository.findByEmail(email).get();
            Boolean flag = user.getIsVerified();
            if (flag) {
                Random random = new Random();
                Integer newOtp = random.nextInt(10000, 99999);
                String subject = RESET_PASSWORD_OTP_EMAIL_SUBJECT;
                String message = RESET_PASSWORD_OTP_EMAIL_MESSAGE + newOtp;
                sendingEmail(email, message, subject);


                return new ResponseEntity<ResetPasswordResponse>(ResetPasswordResponse.builder()
                        .email(email)
                        .message("OTP Send Sucessfully on email" + email)
                        .build(), HttpStatus.OK);
            } else {
                return new ResponseEntity<ResetPasswordResponse>(ResetPasswordResponse.builder()
                        .email(email)
                        .message("OTP Verification Needed Before Reset password")
                        .build(), HttpStatus.BAD_REQUEST);

            }
        } catch (Exception e) {
            return new ResponseEntity<ResetPasswordResponse>(ResetPasswordResponse.builder()
                    .email(email)
                    .message(e.toString())
                    .build(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
*/

    private ValidationResponse validateSignUpRequest(SignUpRequest signUpRequest) {
        if (signUpRequest.getEmail() == null || signUpRequest.getEmail().isEmpty() || signUpRequest.getEmail().equals("null")) {
            return new ValidationResponse(false, "Email is required");
        }
        if (signUpRequest.getFirstName() == null || signUpRequest.getFirstName().isEmpty() || signUpRequest.getFirstName().equals("null")) {
            return new ValidationResponse(false, "First name is required");
        }
        if (signUpRequest.getLastName() == null || signUpRequest.getLastName().isEmpty() || signUpRequest.getLastName().equals("null")) {
            return new ValidationResponse(false, "Last name is required");
        }
        if (signUpRequest.getPassword() == null || signUpRequest.getPassword().isEmpty() || signUpRequest.getPassword().equals("null")) {
            return new ValidationResponse(false, "Password is required");
        }
        return new ValidationResponse(true, "Valid sign-up request");
    }


    public boolean isValidLogInRequest(LogInRequest logInRequest) {
        return logInRequest != null && logInRequest.getEmail() != null && !logInRequest.getEmail().isEmpty() && logInRequest.getPassword() != null && !logInRequest.getPassword().isEmpty();
    }

    private boolean isValidEmail(String email) {
        String emailRegExp = EmailRegExp.EMAIL_PATTERN.getPattern();
        return email != null && email.matches(emailRegExp);
    }

    private boolean isValidPassword(String password) {
        String passwordRegExp = PasswordRegExp.PASSWORD_PATTERN.getPattern();
        return password != null && password.matches(passwordRegExp);
    }

    private void sendingEmail(String message, String subject, String email) {
        try {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, true);

            Context context = new Context();

            mimeMessageHelper.setTo(email);
            mimeMessageHelper.setSubject(subject);

            context.setVariable("content", message);
            String processedString = templateEngine.process("EmailTemplateForOTP", context);

            mimeMessageHelper.setText(processedString, true);

            javaMailSender.send(mimeMessage);
        } catch (Exception e) {
            logger.error(e.toString());
        }
    }

    private void doAuthenticate(String email, String password) {

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(email, password);
        try {
            authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        } catch (Exception e) {
            logger.error(e.toString());
        }
    }

    public boolean validateParameters(String email, String newPassword, String confirmPassword) {
        boolean isValid = true;

        if (!isValidEmail(email)) {
            isValid = false;
        }

        if (!isValidPassword(newPassword)) {
            isValid = false;
        }

        if (!newPassword.equals(confirmPassword)) {
            isValid = false;
        }

        return isValid;
    }

    @Getter
    private enum EmailRegExp {
        EMAIL_PATTERN("^(?=.{1,64}@)[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*@" + "[^-][A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*(\\.[A-Za-z]{2,})$");

        private final String pattern;

        EmailRegExp(String pattern) {
            this.pattern = pattern;
        }

    }

    @Getter
    private enum PasswordRegExp {
        PASSWORD_PATTERN("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,20}$");

        private final String pattern;

        PasswordRegExp(String pattern) {
            this.pattern = pattern;
        }

    }

}
