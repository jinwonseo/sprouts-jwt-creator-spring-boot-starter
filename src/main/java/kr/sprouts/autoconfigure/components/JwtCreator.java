package kr.sprouts.autoconfigure.components;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;

import java.security.Key;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.UUID;

public class JwtCreator {
    private final Logger logger = LoggerFactory.getLogger(JwtCreator.class);

    public JwtCreator() {
        this.logger.info(String.format("Initialized %s", JwtCreator.class.getName()));
    }

    public static String create(@NonNull Claims claims, @NonNull Key key, @NonNull SignatureAlgorithm signatureAlgorithm) {
        return Jwts.builder()
                .setClaims(claims)
                .signWith(key, signatureAlgorithm)
                .compact();
    }

    public static String create(@NonNull Claims claims, @NonNull String base64UrlEncodedSecret, @NonNull SignatureAlgorithm signatureAlgorithm) {
        return JwtCreator.create(
                claims,
                JwtHelper.convertToKey(base64UrlEncodedSecret),
                signatureAlgorithm);
    }

    public static String create(@NonNull Key key, @NonNull SignatureAlgorithm signatureAlgorithm) {
        Claims claims = Jwts.claims();
        claims.setId(UUID.randomUUID().toString());

        return Jwts.builder()
                .setClaims(claims)
                .signWith(key, signatureAlgorithm)
                .compact();
    }

    public static String create(@NonNull String base64UrlEncodedSecret, @NonNull SignatureAlgorithm signatureAlgorithm) {
        return JwtCreator.create(
                JwtHelper.convertToKey(base64UrlEncodedSecret),
                signatureAlgorithm
        );
    }

    public static String create(@NonNull String issuer, @NonNull String subject, @NonNull String audience, @NonNull Long validityInSeconds, @NonNull String base64UrlEncodedSecret, @NonNull SignatureAlgorithm signatureAlgorithm) {
        LocalDateTime currentLocalDateTime = LocalDateTime.now();

        Claims claims = Jwts.claims();
        claims.setId(UUID.randomUUID().toString());
        claims.setIssuer(issuer);
        claims.setSubject(subject);
        claims.setAudience(audience);
        claims.setNotBefore(Timestamp.valueOf(currentLocalDateTime));
        claims.setIssuedAt(Timestamp.valueOf(currentLocalDateTime));
        claims.setExpiration(Timestamp.valueOf(currentLocalDateTime.plusSeconds(validityInSeconds)));

        return JwtCreator.create(
                claims,
                JwtHelper.convertToKey(base64UrlEncodedSecret),
                signatureAlgorithm
        );
    }
}
