package com.clientRackr.api.controllerImpl;

import com.clientRackr.api.auth.JwtUtil;
import com.clientRackr.api.wrapper.ErrorResponse;
import com.clientRackr.api.wrapper.SignUpRequest;
import com.clientRackr.api.wrapper.TokenResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;


@Controller
@RequestMapping("/rest")
public class TokenGenerationController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public TokenGenerationController(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @ResponseBody
    @RequestMapping(value = "/token", method = RequestMethod.POST)
    public ResponseEntity signUp(@RequestBody SignUpRequest signUpRequest) {

        try {
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(signUpRequest.getEmail(),
                            signUpRequest.getPassword()));
            String email = authentication.getName();
            String token = jwtUtil.generateToken(signUpRequest);
            TokenResponse tokenResponse = new TokenResponse(email, token);
            return ResponseEntity.ok(tokenResponse);

        } catch (BadCredentialsException e) {
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.BAD_REQUEST, "Invalid username or password");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        } catch (Exception e) {
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.BAD_REQUEST, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }
    }
}
