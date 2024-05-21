package com.clientRackr.api.servicesImpl;

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
import org.aspectj.apache.bcel.classfile.Code;
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

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;

@Service
public class AuthServiceImpl implements AuthService {

    public static final String RESEND_OTP_MAIL_SUBJECT = "Your New OTP Code";
    public static final String RESEND_OTP_MAIL_MESSAGE = "To complete your verification process, New OTP is : ";
    public static final String ACCOUNT_REGISTRATION_EMAIL_SUBJECT = "Verification Code for Account Registration";
    public static final String RESET_PASSWORD_LINK_EMAIL_SUBJECT = "This mail for Forget Password";
    public static final String OTP_MAIL_MESSAGE_FORMAT = "Your one-time password is ";
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
        String email = signUpRequest.getEmail();
        Integer otp = signUpRequest.getOTP();
        OTP existingOTP = otpRepository.findByEmail(email);
        logger.info("Entering AuthServiceImpl :: registerUser method...");
        try {
            String signUpRequestJson = objectMapper.writeValueAsString(signUpRequest);
            logger.info("SignUpRequest: {}", signUpRequestJson);

            if (isValidSignUpRequest(signUpRequest)) {
                logger.debug("inside the if block of registerUser method..");
                Optional<User> existingUser = userRepository.findByEmail(signUpRequest.getEmail());
                if (!existingUser.isEmpty()) {
                    logger.error("User already exists");
                    return new ResponseEntity("User already exists", HttpStatus.BAD_REQUEST);

                } else {
                    if (isValidEmail(signUpRequest.getEmail()) && isValidPassword(signUpRequest.getPassword())) {
                        LocalDateTime creationTime = existingOTP.getOtpTimestamp();
                        LocalDateTime currentTime = LocalDateTime.now();
                        Duration duration = Duration.between(creationTime, currentTime);
                        long minutesPassed = duration.toMinutes();
                        if(minutesPassed <= 5){
                            User user = new User();
                            user.setEmail(signUpRequest.getEmail());
                            user.setFirstName(signUpRequest.getFirstName());
                            user.setLastName(signUpRequest.getLastName());
                            user.setPassword(bCryptPasswordEncoder.encode(signUpRequest.getPassword()));
                            userRepository.save(user);

                            logger.info("User saved successfully");
                            return new ResponseEntity("User saved successfully", HttpStatus.CREATED);
                        } else {
                            return new ResponseEntity("Invalid OTP", HttpStatus.UNAUTHORIZED);
                        }
                    } else {
                        logger.error("Invalid email or password");
                        return new ResponseEntity(HttpStatus.BAD_REQUEST);
                    }
                }
            } else {
                logger.warn("Invalid sign-up request");
                return new ResponseEntity("Invalid sign-up request", HttpStatus.BAD_REQUEST);
            }
        } catch (Exception e) {
            logger.error("An error occurred", e);
            return new ResponseEntity("Invalid sign-up request", HttpStatus.BAD_REQUEST);
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

                User existingUser = userRepository.findByEmail(userEmail)
                        .orElseThrow(() -> new EntityNotFoundException("User not found"));
                String existingUserPassword = existingUser.getPassword();

                logger.info("Authenticating user...");
                this.doAuthenticate(userEmail, userPassword);
                UserDetails userDetails = userDetailsService.loadUserByUsername(logInRequest.getEmail());

                if (userPassword != null && bCryptPasswordEncoder.matches(userPassword, existingUserPassword)) {
                    String token = jwtUtil.createToken(logInRequest);

                    response = LogInResponse.builder().message("Successfully logged in")
                            .email(userDetails.getUsername())
                            .token(token).build();

                    logger.info("User logged in successfully.");

                    return new ResponseEntity<>(response, HttpStatus.OK);
                } else {
                    return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
                }
            }
        } catch (EntityNotFoundException e) {
            logger.error("User not found", e);
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(LogInResponse.builder().email(logInRequest.getEmail()).message("Invalid email or password").build());
        } catch (Exception e) {
            logger.error("An error occurred", e);
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        logger.info("AuthServiceImpl :: login method end...");
        return null;
    }



    @Override
    public ResponseEntity<ResetPasswordResponse> resetPassword(ResetPasswordRequest resetPasswordRequest, HttpServletRequest request) {
        String newPassword = resetPasswordRequest.getNewPassword();
        String confirmPassword = resetPasswordRequest.getConfirmPassword();
        String email = resetPasswordRequest.getEmail();
        User existUser = userRepository.findByEmail(email).get();
        Boolean validatorResponse = validateParameters(email, newPassword, confirmPassword);
        if (existUser.getPassword()!=null && validatorResponse) {
            if (!bCryptPasswordEncoder.matches(newPassword, existUser.getPassword())) {
                if (newPassword.equals(confirmPassword)) {
                    String encodedPassword = bCryptPasswordEncoder.encode(newPassword);
                    existUser.setPassword(encodedPassword);
                    userRepository.save(existUser);
                    return ResponseEntity.status(HttpStatus.OK)
                            .body(new ResetPasswordResponse(resetPasswordRequest.getEmail(), "Password Updated Sucessfully"));

                } else {
                    return new ResponseEntity("you confirm password are not same as new password",HttpStatus.BAD_REQUEST);
                }
            } else {
                return new ResponseEntity("you new password should not be same as old password",HttpStatus.BAD_REQUEST);
            }
        } else {
            return new ResponseEntity("Password should not be null or should be strong",HttpStatus.BAD_REQUEST);
        }
    }

    @Override
    public OTP saveOtp(String email) {
        OTP otpEntity = null;
        Optional<User> existingUser = userRepository.findByEmail(email);
        if (existingUser.isEmpty()) {
            otpEntity = otpService.createOtp(email);
            Integer otp = otpEntity.getOneTimePassword();
            String message = OTP_MAIL_MESSAGE_FORMAT + otp;
            sendingEmail(message, ACCOUNT_REGISTRATION_EMAIL_SUBJECT, email);
            otpRepository.save(otpEntity);
        }else {
            // need to make scenario for existing otp+email
        }
        return otpEntity;
    }

    @Override
    public ResponseEntity<String> PasswordResetLink(PasswordResetLinkRequest passwordResetLinkRequest) {
        String email = passwordResetLinkRequest.getEmail();
        try {
            User getUser = userRepository.findByEmail(email).get();
            String message = "This reset link is only for this email : " + email;
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, true);

            Context context = new Context();

            mimeMessageHelper.setTo(getUser.getEmail());
            mimeMessageHelper.setSubject(RESET_PASSWORD_LINK_EMAIL_SUBJECT);

            context.setVariable("content", message);
            String processedString = templateEngine.process("ForgetPassword", context);

            mimeMessageHelper.setText(processedString, true);

            javaMailSender.send(mimeMessage);
            return new ResponseEntity<>("Reset password link send on your given email id", HttpStatus.OK);
        } catch (Exception ex) {
            ex.printStackTrace();
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
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

                    String message = RESEND_OTP_MAIL_MESSAGE + newOtp;
                    sendingEmail(message, RESEND_OTP_MAIL_SUBJECT, email);
                    otp.setOneTimePassword(newOtp);
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


    private boolean isValidSignUpRequest(SignUpRequest signUpRequest) {
        return signUpRequest != null &&
                signUpRequest.getEmail() != null &&
                !signUpRequest.getEmail().isEmpty() &&
                signUpRequest.getFirstName() != null &&
                !signUpRequest.getFirstName().isEmpty() &&
                signUpRequest.getLastName() != null &&
                !signUpRequest.getLastName().isEmpty() &&
                signUpRequest.getPassword() != null &&
                !signUpRequest.getPassword().isEmpty();
    }

    public boolean isValidLogInRequest(LogInRequest logInRequest) {
        return logInRequest != null
                && logInRequest.getEmail() != null && !logInRequest.getEmail().isEmpty()
                && logInRequest.getPassword() != null && !logInRequest.getPassword().isEmpty();
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

    @Getter
    private enum EmailRegExp {
        EMAIL_PATTERN("^(?=.{1,64}@)[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*@" +
                "[^-][A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*(\\.[A-Za-z]{2,})$");

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

}
