package com.example.securityjwtdemo.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {

    @Query(value = """
            select t.* from token t inner join users u on t.user_id = u.id
            where u.id = :userId and (t.expired = false and t.revoked = false)
            """, nativeQuery = true)
    List<Token> findAllValidTokensByUser(Long userId);

    Optional<Token> findByToken(String token);
}
