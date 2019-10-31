package org.springframework.security.oauth2.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSimpleVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.List;

import reactor.core.publisher.Mono;

public class SignerReactiveSimpleJwtDecoder implements ReactiveJwtDecoder {

  private static final BadJOSEException NO_MATCHING_VERIFIERS_EXCEPTION =
      new BadJOSEException("JWS object rejected: No matching verifier(s) found");
  
  private final JWSVerifier verifier;
  
  public SignerReactiveSimpleJwtDecoder(String algorithm, String strKey) throws JOSEException {
    JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(algorithm);
    OctetSequenceKey secretKey = secretKey(strKey, jwsAlgorithm);
    verifier = new MACSimpleVerifier(secretKey);
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
  
  private static OctetSequenceKey secretKey(String secretKey, JWSAlgorithm jwsAlgorithm) {
    final byte[] keyChanllenge = secretKey.getBytes(StandardCharsets.UTF_8);
    return new OctetSequenceKey.Builder(keyChanllenge).algorithm(jwsAlgorithm)
        .build();
  }
  
  private JWTClaimsSet createClaimsSet(JWT parsedToken) {
    try {
      
      if (parsedToken instanceof SignedJWT) {
        SignedJWT signedJWT = (SignedJWT) parsedToken;
        final boolean validSignature = signedJWT.verify(verifier);
        if (validSignature) {
          return verifyAndReturnClaims(signedJWT, context);
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
  
  private JWTClaimsSet verifyAndReturnClaims(final JWT jwt, final C context)
      throws BadJWTException {

      JWTClaimsSet claimsSet;

      try {
        claimsSet = jwt.getJWTClaimsSet();

      } catch (ParseException e) {
        // Payload not a JSON object
        throw new BadJWTException(e.getMessage(), e);
      }

      if (getJWTClaimsSetVerifier() != null) {
        getJWTClaimsSetVerifier().verify(claimsSet, context);
      } else if (getJWTClaimsVerifier() != null) {
        // Fall back to deprecated claims verifier
        getJWTClaimsVerifier().verify(claimsSet);
      }

      return claimsSet;
    }
}
