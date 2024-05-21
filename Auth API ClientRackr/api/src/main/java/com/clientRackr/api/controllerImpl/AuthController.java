package com.clientRackr.api.controllerImpl;

import com.clientRackr.api.IServices.AuthService;
import com.clientRackr.api.auth.JwtUtil;
import com.clientRackr.api.entity.OTP;
import com.clientRackr.api.repository.UserRepository;
import com.clientRackr.api.wrapper.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;


@Controller
@RequestMapping("/rest/auth")
public class AuthController {

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


    @ResponseBody
    @RequestMapping(value = "/signUp", method = RequestMethod.POST)
    public ResponseEntity signUp(@RequestBody SignUpRequest signUpRequest) {

        try {
            ResponseEntity response = authService.registerUser(signUpRequest);
            if (response.getStatusCode() == HttpStatus.BAD_REQUEST) {
                return new ResponseEntity("User already exist", HttpStatus.BAD_REQUEST);
            } else if (response.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                return new ResponseEntity("Invalid OTP", HttpStatus.UNAUTHORIZED);
            }

            SignUpResponse signUpResponse = new SignUpResponse(signUpRequest.getEmail(), "User created successfully");
            return ResponseEntity.ok(signUpResponse);

        } catch (BadCredentialsException e) {
            ErrorRes errorResponse = new ErrorRes(HttpStatus.BAD_REQUEST, "Invalid username or password");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        } catch (Exception e) {
            ErrorRes errorResponse = new ErrorRes(HttpStatus.BAD_REQUEST, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<LogInResponse> login(@RequestBody LogInRequest logInRequest, HttpServletRequest request) {
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

    @PostMapping("/reset-password")
    public ResponseEntity<ResetPasswordResponse> resetPassword(@RequestBody ResetPasswordRequest resetPasswordRequest, HttpServletRequest request) {
        return authService.resetPassword(resetPasswordRequest, request);
    }

    @PostMapping("/save-otp")
    public ResponseEntity<OTP> otpVerification(@RequestParam String email) {
        OTP response = authService.saveOtp(email);
        if (response != null) {
            return new ResponseEntity<>(response, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/PasswordResetLink")
    public ResponseEntity<String> PasswordResetLink(@RequestBody  PasswordResetLinkRequest passwordResetLinkRequest) {
        return authService.PasswordResetLink(passwordResetLinkRequest);
    }

    @PostMapping("/resendOTP")
    public ResponseEntity<String> resendOTP(@RequestParam String email)     {
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