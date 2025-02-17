package com.datau.dolbau.api.v1.auth.oauth2.apple;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;

@Component
public class AppleClientSecretGenerator {
    private static final int SECOND = 1000;
    private static final int MINUTE = 60 * SECOND;
    private static final int HOUR = 60 * MINUTE;

    @Value("${spring.security.oauth2.external-service.apple.team-id}")
    private String teamId;

    @Value("${spring.security.oauth2.external-service.apple.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.external-service.apple.key-id}")
    private String keyId;

    @Value("${spring.security.oauth2.external-service.apple.key-path}")
    private String keyPath;

    @Value("${spring.security.oauth2.external-service.apple.auth-url}")
    private String authUrl;

    public String createClientSecret() {
        Date now = new Date();
        Date expirationTime = new Date(now.getTime() + HOUR);
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(keyId).build();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(teamId)
                .audience(authUrl)
                .subject(clientId)
                .issueTime(now)
                .expirationTime(expirationTime)
                .build();

        SignedJWT jwt = new SignedJWT(header, claimsSet);

        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(getPrivateKey(keyPath));
            KeyFactory kf = KeyFactory.getInstance("EC");

            ECPrivateKey ecPrivateKey = (ECPrivateKey) kf.generatePrivate(spec);
            JWSSigner jwsSigner = new ECDSASigner(ecPrivateKey);
            jwt.sign(jwsSigner);
        } catch (JOSEException e) {
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return jwt.serialize();
    }

    private byte[] getPrivateKey(String keyPath) throws IOException {
        byte[] content = null;
        ClassPathResource resource = new ClassPathResource(keyPath);
        Reader keyReader = new InputStreamReader(resource.getInputStream());
        PemReader pemReader = new PemReader(keyReader);
        PemObject pemObject = pemReader.readPemObject();
        content = pemObject.getContent();
        return content;
    }


}
