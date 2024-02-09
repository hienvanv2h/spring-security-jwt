package com.example.securityjwtdemo.token;

import com.example.securityjwtdemo.dto.AuthenticationResponse;
import com.example.securityjwtdemo.dto.RefreshTokenRequest;
import com.example.securityjwtdemo.exceptions.RefreshTokenException;
import com.example.securityjwtdemo.user.UserRepository;
import com.example.securityjwtdemo.util.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshTokenExpiration;

    public RefreshToken createRefreshToken(String username) {
        var user = userRepository.findByEmail(username)
                        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        // check if token exist in db -> delete it can create a new one
        Optional<RefreshToken> validateToken = refreshTokenRepository.findByUserId(user.getId());
        validateToken.ifPresent(refreshTokenRepository::delete);

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID() + "_" + Instant.now())
                .expireAt(Instant.now().plusMillis(refreshTokenExpiration))
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if(token.getExpireAt().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new RefreshTokenException("Refresh token was expired. Please make a new sign in request");
        }
        return token;
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }
}
