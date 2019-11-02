package com.mplescano.apps.poc.components.jwt;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.CriticalHeaderParamsAware;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.crypto.impl.HMAC;
import com.nimbusds.jose.crypto.utils.ConstantTimeUtils;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StandardCharset;

/**
 * The base abstract class for Message Authentication Code (MAC) signers and
 * verifiers of {@link com.nimbusds.jose.JWSObject JWS objects}.
 * <p>
 * Supports the following algorithms:
 * <ul>
 * <li>{@link com.nimbusds.jose.JWSAlgorithm#HS256}
 * <li>{@link com.nimbusds.jose.JWSAlgorithm#HS384}
 * <li>{@link com.nimbusds.jose.JWSAlgorithm#HS512}
 * </ul>
 * 
 * @author Vladimir Dzhuvinov
 * @version 2016-07-27
 */
public class MACSimpleVerifier extends BaseJWSProvider implements JWSVerifier, CriticalHeaderParamsAware {

    /**
     * The critical header policy.
     */
    private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();

    /**
     * The supported JWS algorithms by the MAC provider class.
     */
    public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;

    static {
        Set<JWSAlgorithm> algs = new LinkedHashSet<>();
        algs.add(JWSAlgorithm.HS256);
        algs.add(JWSAlgorithm.HS384);
        algs.add(JWSAlgorithm.HS512);
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
    }

    /**
     * Gets the matching Java Cryptography Architecture (JCA) algorithm
     * name for the specified HMAC-based JSON Web Algorithm (JWA).
     *
     * @param alg The JSON Web Algorithm (JWA). Must be supported and not
     *            {@code null}.
     * @return The matching JCA algorithm name.
     * @throws JOSEException If the algorithm is not supported.
     */
    protected static String getJCAAlgorithmName(final JWSAlgorithm alg) throws JOSEException {

        if (alg.equals(JWSAlgorithm.HS256)) {
            return "HMACSHA256";
        }
        else if (alg.equals(JWSAlgorithm.HS384)) {
            return "HMACSHA384";
        }
        else if (alg.equals(JWSAlgorithm.HS512)) {
            return "HMACSHA512";
        }
        else {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, SUPPORTED_ALGORITHMS));
        }
    }

    /**
     * The secret.
     */
    private final byte[] secret;

    public MACSimpleVerifier(final byte[] secret) {

        this(secret, null);
    }

    public MACSimpleVerifier(final String secretString) {

        this(secretString.getBytes(StandardCharset.UTF_8));
    }

    public MACSimpleVerifier(final SecretKey secretKey) {
        this(secretKey.getEncoded());
    }

    public MACSimpleVerifier(final byte[] secret, final Set<String> defCritHeaders) {
        super(SUPPORTED_ALGORITHMS);
        this.secret = secret;
        critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
    }

    public MACSimpleVerifier(final OctetSequenceKey jwk) {
        this(jwk.toByteArray());
    }

    /**
     * Gets the secret key.
     *
     * @return The secret key.
     */
    public SecretKey getSecretKey() {

        return new SecretKeySpec(secret, "MAC");
    }

    /**
     * Gets the secret bytes.
     *
     * @return The secret bytes.
     */
    public byte[] getSecret() {

        return secret;
    }

    /**
     * Gets the secret as a UTF-8 encoded string.
     *
     * @return The secret as a UTF-8 encoded string.
     */
    public String getSecretString() {

        return new String(secret, StandardCharset.UTF_8);
    }

    @Override
    public Set<String> getProcessedCriticalHeaderParams() {

        return critPolicy.getProcessedCriticalHeaderParams();
    }

    @Override
    public Set<String> getDeferredCriticalHeaderParams() {

        return critPolicy.getProcessedCriticalHeaderParams();
    }

    @Override
    public boolean verify(final JWSHeader header, final byte[] signedContent, final Base64URL signature)
            throws JOSEException {

        if (!critPolicy.headerPasses(header)) {
            return false;
        }

        String jcaAlg = getJCAAlgorithmName(header.getAlgorithm());
        byte[] expectedHMAC = HMAC.compute(jcaAlg, getSecret(), signedContent, getJCAContext().getProvider());
        return ConstantTimeUtils.areEqual(expectedHMAC, signature.decode());
    }
}
