package com.clientRackr.api.controllerImpl;

import com.clientRackr.api.IServices.AuthService;
import com.clientRackr.api.auth.JwtUtil;
import com.clientRackr.api.repository.UserRepository;
import com.clientRackr.api.wrapper.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;




@RestController
@RequestMapping("/rest/auth")
@Slf4j
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    @Autowired
    private AuthService authService;

    @Autowired
    private UserRepository userRepository;

    public AuthController(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }


    @PostMapping(value = "/signUp")
    public ResponseEntity<?> signUp(@RequestBody @Valid SignUpRequest signUpRequest) {
        try {
            ResponseEntity<SignUpResponse> response = authService.registerUser(signUpRequest);

            if (response.getStatusCode() == HttpStatus.BAD_REQUEST || response.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                return response;
            }

            if (response.getStatusCode() == HttpStatus.CREATED) {
                SignUpResponse signUpResponse = response.getBody();
                return ResponseEntity.ok(signUpResponse);
            }
            return response;
        } catch (BadCredentialsException e) {
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.BAD_REQUEST, "Invalid username or password");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        } catch (Exception e) {
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<LogInResponse> login(@RequestBody @Validated LogInRequest logInRequest, HttpServletRequest request) {
        try {
            if (logInRequest != null) {
//                String token = jwtUtil.createToken(signUpRequest); // only for response
                return authService.login(logInRequest, request);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @PostMapping("/resetPassword")
    public ResponseEntity<ResetPasswordResponse> resetPassword(@RequestBody ResetPasswordRequest resetPasswordRequest, HttpServletRequest request) {
        return authService.resetPassword(resetPasswordRequest, request);
    }

    @PostMapping("/verifyOTP")
    public ResponseEntity<OTPVerificationResponse> verifyOTP(@RequestParam Integer OTP, @RequestParam String email) {
        try {
            if (email != null && OTP != null)
                return authService.verifyOTP(email, OTP);
        } catch (Exception e) {
            logger.error(e.toString());
        }
        return null;
    }


    /*    @PostMapping("/save-otp")
    public ResponseEntity<?> otpVerification(@RequestParam String email) {
        logger.info("Entering otpVerification method with email: {}", email);

        try {
            OTP response = authService.saveOtp(email);

            if (response != null) {
                logger.info("OTP generated and sent to email: {}", email);
                return new ResponseEntity<>(response, HttpStatus.OK);
            } else {
                logger.warn("User already exists with email: {}", email);
                ErrorResponse errorResponse = new ErrorResponse("User already exists", HttpStatus.BAD_REQUEST);
                return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
            }
        } catch (Exception e) {
            logger.error("An error occurred while generating OTP for email: {}", email, e);
            ErrorResponse errorResponse = new ErrorResponse("An error occurred while generating OTP", HttpStatus.INTERNAL_SERVER_ERROR);
            return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }*/


    /*@PostMapping("/PasswordResetLink")
    public ResponseEntity<String> PasswordResetLink(@RequestBody PasswordResetLinkRequest passwordResetLinkRequest) {
        return authService.PasswordResetLink(passwordResetLinkRequest);
    }*/

    /*@PostMapping("/PasswordResetOTP")
    public ResponseEntity<ResetPasswordResponse> PasswordResetOTP(@RequestBody PasswordResetOTPRequest passwordResetOTPRequest) {
        return authService.PasswordResetOTP(passwordResetOTPRequest);
    }*/


    @PostMapping("/resendOTP")
    public ResponseEntity<String> resendOTP(@RequestParam String email) {
        try {
            if (email != null || !email.contains(""))
                return authService.resendOTP(email);
        } catch (Exception e) {
            e.printStackTrace();
//            logger.error(e.toString());
        }
        return null;
    }
}