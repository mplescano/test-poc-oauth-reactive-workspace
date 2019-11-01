package com.mplescano.apps.poc.components.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSimpleVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import reactor.core.publisher.Mono;

public class SignerReactiveSimpleJwtDecoder implements ReactiveJwtDecoder {

    private static final String DEFAULT_ALGORITHM = JwsAlgorithms.HS256;

    private static final BadJOSEException NO_MATCHING_VERIFIERS_EXCEPTION = new BadJOSEException(
            "JWS object rejected: No matching verifier(s) found");

    private OAuth2TokenValidator<Jwt> jwtValidator = new DelegatingOAuth2TokenValidator<>(Arrays.asList(new JwtTimestampValidator()));

    private final JWSVerifier verifier;

    public SignerReactiveSimpleJwtDecoder(String algorithm, String strKey) {
        JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(algorithm);
        OctetSequenceKey secretKey = secretKey(strKey, jwsAlgorithm);
        verifier = new MACSimpleVerifier(secretKey);
    }

    public SignerReactiveSimpleJwtDecoder(String strKey) {
        this(DEFAULT_ALGORITHM, strKey);
    }

    @Override
    public Mono<Jwt> decode(String token) throws JwtException {
        JWT jwt = parse(token);
        if (jwt instanceof SignedJWT) {
            return this.decode((SignedJWT) jwt);
        }
        throw new JwtException("Unsupported algorithm of " + jwt.getHeader().getAlgorithm());
    }

    private JWT parse(String token) {
        try {
            return JWTParser.parse(token);
        }
        catch (Exception ex) {
            throw new JwtException("An error occurred while attempting to decode the Jwt: " + ex.getMessage(), ex);
        }
    }

    private static OctetSequenceKey secretKey(String secretKey, JWSAlgorithm jwsAlgorithm) {
        final byte[] keyChanllenge = secretKey.getBytes(StandardCharsets.UTF_8);
        return new OctetSequenceKey.Builder(keyChanllenge).algorithm(jwsAlgorithm).build();
    }

    private JWTClaimsSet createClaimsSet(JWT parsedToken) {
        try {

            if (parsedToken instanceof SignedJWT) {
                SignedJWT signedJWT = (SignedJWT) parsedToken;
                final boolean validSignature = signedJWT.verify(verifier);
                if (validSignature) {
                    return verifyAndReturnClaims(signedJWT);
                }

                throw NO_MATCHING_VERIFIERS_EXCEPTION;
            }

            // Should never happen
            throw new JOSEException("Unexpected JWT object type: " + parsedToken.getClass());
        }
        catch (BadJOSEException | JOSEException e) {
            throw new JwtException("Failed to validate the token", e);
        }
    }

    private JWTClaimsSet verifyAndReturnClaims(final JWT jwt) throws BadJWTException {

        JWTClaimsSet claimsSet;

        try {
            claimsSet = jwt.getJWTClaimsSet();

        }
        catch (ParseException e) {
            // Payload not a JSON object
            throw new BadJWTException(e.getMessage(), e);
        }
        return claimsSet;
    }

    private Mono<Jwt> decode(SignedJWT parsedToken) {
        try {
            return Mono.just(createClaimsSet(parsedToken)).map(set -> createSpringJwt(parsedToken, set))
                    .map(this::validateJwt)
                    .onErrorMap(e -> !(e instanceof IllegalStateException) && !(e instanceof JwtException),
                            e -> new JwtException("An error occurred while attempting to decode the Jwt: ", e));
        }
        catch (RuntimeException ex) {
            throw new JwtException("An error occurred while attempting to decode the Jwt: " + ex.getMessage(), ex);
        }
    }

    private Jwt validateJwt(Jwt jwt) {
        OAuth2TokenValidatorResult result = this.jwtValidator.validate(jwt);

        if (result.hasErrors()) {
            String message = result.getErrors().iterator().next().getDescription();
            throw new JwtValidationException(message, result.getErrors());
        }

        return jwt;
    }

    private Jwt createSpringJwt(JWT parsedJwt, JWTClaimsSet jwtClaimsSet) {
        Instant expiresAt = null;
        if (jwtClaimsSet.getExpirationTime() != null) {
            expiresAt = jwtClaimsSet.getExpirationTime().toInstant();
        }
        Instant issuedAt = null;
        if (jwtClaimsSet.getIssueTime() != null) {
            issuedAt = jwtClaimsSet.getIssueTime().toInstant();
        }
        else if (expiresAt != null) {
            // Default to expiresAt - 1 second
            issuedAt = Instant.from(expiresAt).minusSeconds(1);
        }

        Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());

        return new Jwt(parsedJwt.getParsedString(), issuedAt, expiresAt, headers, jwtClaimsSet.getClaims());
    }
}
