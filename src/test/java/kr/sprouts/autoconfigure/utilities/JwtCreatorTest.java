package kr.sprouts.autoconfigure.utilities;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.security.PrivateKey;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtCreatorTest {

    private static Claims parse(Key key, String claimsJws) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(claimsJws).getBody();
    }

    private static Claims parse(String base64UrlEncodedSecret, String claimsJws) {
        return Jwts.parserBuilder().setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(Base64.getUrlEncoder().encodeToString(base64UrlEncodedSecret.getBytes())))).build().parseClaimsJws(claimsJws).getBody();
    }

    @Test
    void create_hs512_using_key() {
        String id = UUID.randomUUID().toString();
        String issuer = UUID.randomUUID().toString();
        String subject = UUID.randomUUID().toString();
        String audience = UUID.randomUUID().toString();
        long validityInSeconds = 60L;

        LocalDateTime currentLocalDateTime = LocalDateTime.now();

        Claims claims = Jwts.claims();
        claims.setId(id);
        claims.setIssuer(issuer);
        claims.setSubject(subject);
        claims.setAudience(audience);
        claims.setNotBefore(Timestamp.valueOf(currentLocalDateTime));
        claims.setIssuedAt(Timestamp.valueOf(currentLocalDateTime));
        claims.setExpiration(Timestamp.valueOf(currentLocalDateTime.plusSeconds(validityInSeconds)));

        Key key = JwtHelper.secretKeyFor(SignatureAlgorithm.HS512);

        assertThat(JwtCreatorTest.parse(key, JwtCreator.create(claims, key, SignatureAlgorithm.HS512)).getId().equals(claims.getId())).isTrue();
    }

    @Test
    void create_hs512_using_secret() {
        String id = UUID.randomUUID().toString();
        String issuer = UUID.randomUUID().toString();
        String subject = UUID.randomUUID().toString();
        String audience = UUID.randomUUID().toString();
        long validityInSeconds = 60L;

        LocalDateTime currentLocalDateTime = LocalDateTime.now();

        Claims claims = Jwts.claims();
        claims.setId(id);
        claims.setIssuer(issuer);
        claims.setSubject(subject);
        claims.setAudience(audience);
        claims.setNotBefore(Timestamp.valueOf(currentLocalDateTime));
        claims.setIssuedAt(Timestamp.valueOf(currentLocalDateTime));
        claims.setExpiration(Timestamp.valueOf(currentLocalDateTime.plusSeconds(validityInSeconds)));

        String base64UrlEncodedSecret = JwtHelper.base64urlEncodedSecretKeyFor(SignatureAlgorithm.HS512).value();

        assertThat(JwtCreatorTest.parse(base64UrlEncodedSecret, JwtCreator.create(claims, base64UrlEncodedSecret, SignatureAlgorithm.HS512)).getId().equals(claims.getId())).isTrue();
    }

    @Test
    void create_rs256_using_private_key() {
        String id = UUID.randomUUID().toString();
        String issuer = UUID.randomUUID().toString();
        String subject = UUID.randomUUID().toString();
        String audience = UUID.randomUUID().toString();
        long validityInSeconds = 60L;

        LocalDateTime currentLocalDateTime = LocalDateTime.now();

        Claims claims = Jwts.claims();
        claims.setId(id);
        claims.setIssuer(issuer);
        claims.setSubject(subject);
        claims.setAudience(audience);
        claims.setNotBefore(Timestamp.valueOf(currentLocalDateTime));
        claims.setIssuedAt(Timestamp.valueOf(currentLocalDateTime));
        claims.setExpiration(Timestamp.valueOf(currentLocalDateTime.plusSeconds(validityInSeconds)));

        PrivateKey privateKey = JwtHelper.keyPairFor(SignatureAlgorithm.RS256).getPrivate();

        assertThat(JwtCreatorTest.parse(privateKey, JwtCreator.create(claims, privateKey, SignatureAlgorithm.RS256)).getId().equals(claims.getId())).isTrue();
    }

    @Test
    void invalid_jws() {
        String id = UUID.randomUUID().toString();
        String issuer = UUID.randomUUID().toString();
        String subject = UUID.randomUUID().toString();
        String audience = UUID.randomUUID().toString();
        long validityInSeconds = 1L;

        LocalDateTime currentLocalDateTime = LocalDateTime.now();

        Claims claims = Jwts.claims();
        claims.setId(id);
        claims.setIssuer(issuer);
        claims.setSubject(subject);
        claims.setAudience(audience);
        claims.setNotBefore(Timestamp.valueOf(currentLocalDateTime));
        claims.setIssuedAt(Timestamp.valueOf(currentLocalDateTime));
        claims.setExpiration(Timestamp.valueOf(currentLocalDateTime.plusSeconds(validityInSeconds)));

        PrivateKey privateKey = JwtHelper.keyPairFor(SignatureAlgorithm.RS256).getPrivate();
        String claimsJws = JwtCreator.create(claims, privateKey, SignatureAlgorithm.RS256);

        try {
            Thread.sleep(validityInSeconds * 2000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        assertThatThrownBy(() -> JwtCreatorTest.parse(privateKey, claimsJws)).isInstanceOf(ExpiredJwtException.class);
    }
}