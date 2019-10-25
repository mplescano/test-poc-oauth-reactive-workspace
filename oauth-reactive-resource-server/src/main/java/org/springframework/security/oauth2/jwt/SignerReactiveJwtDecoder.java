package org.springframework.security.oauth2.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;

import reactor.core.publisher.Mono;

public class SignerReactiveJwtDecoder implements ReactiveJwtDecoder {

  private static final String DEFAULT_ALGORITHM = JwsAlgorithms.HS256;

  private final JWTProcessor<JWKContext> jwtProcessor;

  private final ReactiveJWKSource reactiveJwkSource;

  private final JWKSelectorFactory jwkSelectorFactory;

  private OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefault();

  public SignerReactiveJwtDecoder(String algorithm, String strKey) {
    JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(algorithm);

    OctetSequenceKey secretKey = secretKey(strKey);
    JWKSet jwkSet = new JWKSet(secretKey);
    JWKSource jwkSource = new ImmutableJWKSet<>(jwkSet);
    JWSKeySelector<JWKContext> jwsKeySelector =
        new JWSVerificationKeySelector<>(jwsAlgorithm, jwkSource);
    DefaultJWTProcessor<JWKContext> jwtProcessorTmp = new DefaultJWTProcessor<>();
    jwtProcessorTmp.setJWSKeySelector(jwsKeySelector);
    jwtProcessorTmp.setJWTClaimsSetVerifier((claims, context) -> {});

    this.jwtProcessor = jwtProcessorTmp;
    this.reactiveJwkSource = new ReactiveJWKSourceAdapter(jwkSource);
    this.jwkSelectorFactory = new JWKSelectorFactory(jwsAlgorithm);
  }

  public SignerReactiveJwtDecoder(String strKey) {
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
    } catch (Exception ex) {
      throw new JwtException("An error occurred while attempting to decode the Jwt: " + ex.getMessage(), ex);
    }
  }
  
  private Mono<Jwt> decode(SignedJWT parsedToken) {
    try {
      JWKSelector selector = this.jwkSelectorFactory.createSelector(parsedToken.getHeader());
      return this.reactiveJwkSource.get(selector)
        .onErrorMap(e -> new IllegalStateException("Could not obtain the keys", e))
        .map(jwkList -> createClaimsSet(parsedToken, jwkList))
        .map(set -> createJwt(parsedToken, set))
        .map(this::validateJwt)
        .onErrorMap(e -> !(e instanceof IllegalStateException) && !(e instanceof JwtException), e -> new JwtException("An error occurred while attempting to decode the Jwt: ", e));
    } catch (RuntimeException ex) {
      throw new JwtException("An error occurred while attempting to decode the Jwt: " + ex.getMessage(), ex);
    }
  }
  
  private Jwt validateJwt(Jwt jwt) {
    OAuth2TokenValidatorResult result = this.jwtValidator.validate(jwt);

    if ( result.hasErrors() ) {
      String message = result.getErrors().iterator().next().getDescription();
      throw new JwtValidationException(message, result.getErrors());
    }

    return jwt;
  }
  
  private Jwt createJwt(JWT parsedJwt, JWTClaimsSet jwtClaimsSet) {
    Instant expiresAt = null;
    if (jwtClaimsSet.getExpirationTime() != null) {
      expiresAt = jwtClaimsSet.getExpirationTime().toInstant();
    }
    Instant issuedAt = null;
    if (jwtClaimsSet.getIssueTime() != null) {
      issuedAt = jwtClaimsSet.getIssueTime().toInstant();
    } else if (expiresAt != null) {
      // Default to expiresAt - 1 second
      issuedAt = Instant.from(expiresAt).minusSeconds(1);
    }

    Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());

    return new Jwt(parsedJwt.getParsedString(), issuedAt, expiresAt, headers, jwtClaimsSet.getClaims());
  }
  
  private static OctetSequenceKey secretKey(String secretKey) {
    return new OctetSequenceKey.Builder(secretKey.getBytes(StandardCharsets.UTF_8))
        .build();
  }
  
  private JWTClaimsSet createClaimsSet(JWT parsedToken, List<JWK> jwkList) {
    try {
      return this.jwtProcessor.process(parsedToken, new JWKContext(jwkList));
    }
    catch (BadJOSEException | JOSEException e) {
      throw new JwtException("Failed to validate the token", e);
    }
  }
}
