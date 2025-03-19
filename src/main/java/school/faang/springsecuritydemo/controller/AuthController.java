package school.faang.springsecuritydemo.controller;

import jakarta.security.auth.message.AuthException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import school.faang.springsecuritydemo.dto.request.LoginRequest;
import school.faang.springsecuritydemo.dto.response.JwtResponse;
import school.faang.springsecuritydemo.dto.request.RegistrationUserRequest;
import school.faang.springsecuritydemo.dto.request.UpdateTokenRequest;
import school.faang.springsecuritydemo.service.AuthService;

@RestController
@RequestMapping("/authorization")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/login")
    public JwtResponse createAuthToken(@RequestBody LoginRequest authRequest) {
        return authService.createAuthToken(authRequest);
    }

    @PostMapping("/refresh-tokens")
    public JwtResponse attemptToRefreshToken(@RequestBody UpdateTokenRequest updateTokenRequest)
            throws AuthException {
        return authService.attemptToRefreshTokens(updateTokenRequest);
    }

    @PostMapping("/registration")
    public ResponseEntity<?> createNewUser(@RequestBody
                                           RegistrationUserRequest registrationUserRequest) {
        return authService.createNewUser(registrationUserRequest);
    }
}