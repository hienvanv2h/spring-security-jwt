package com.example.securityjwtdemo.auth;

import com.example.securityjwtdemo.dto.*;
import com.example.securityjwtdemo.exceptions.RefreshTokenException;
import com.example.securityjwtdemo.token.RefreshToken;
import com.example.securityjwtdemo.token.RefreshTokenService;
import com.example.securityjwtdemo.user.Role;
import com.example.securityjwtdemo.user.User;
import com.example.securityjwtdemo.user.UserRepository;
import com.example.securityjwtdemo.util.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    private final RefreshTokenService refreshTokenService;

    public RegisterResponse register(RegisterRequest request) {
        // check if username already exist in db
        Optional<User> validateUser = userRepository.findByEmail(request.getEmail());
        if(validateUser.isPresent()) {
            return RegisterResponse.builder()
                    .message("Username already exist")
                    .build();
        }

        // create new user and save to database
        Role userRole = request.getRole();
        if(userRole == null) {
            userRole = Role.USER;
        }
        var user = User.builder()
                .firstname(request.getFirstName())
                .lastname(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(userRole)
                .build();
        // save user into db
        userRepository.save(user);
        // generate access token for user
        var jwtToken = jwtService.generateToken(request.getEmail());
        return RegisterResponse.builder()
                .message("User registration successful")
                .accessToken(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        // authenticate user, if not it will auto throw an exception
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );
        if(authentication.isAuthenticated()) {
            // create access token and refresh token + fill response info back to user
            var refreshToken = refreshTokenService.createRefreshToken(request.getEmail());
            var jwtToken = jwtService.generateToken(request.getEmail());
            return AuthenticationResponse.builder()
                    .accessToken(jwtToken)
                    .refreshToken(refreshToken.getToken())
                    .build();
        } else {
            throw new UsernameNotFoundException("Invalid user request");
        }
    }

    public AuthenticationResponse refreshToken(RefreshTokenRequest request) {
        return refreshTokenService.findByToken(request.getToken())
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String jwtToken = jwtService.generateToken(user.getUsername());
                    return AuthenticationResponse.builder()
                            .accessToken(jwtToken)
                            .refreshToken(request.getToken())
                            .build();
                }).orElseThrow(() -> new RefreshTokenException("Refresh token not found"));
    }
}
