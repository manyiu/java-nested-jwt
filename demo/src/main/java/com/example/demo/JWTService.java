package com.example.demo;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.*;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.*;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.Base64;
import java.util.UUID;

public class JWTService {

    public static String signAndEncrypt() {
        byte[] signatureCertByte = new byte[0];
        try {
            signatureCertByte = Files.readAllBytes(Paths.get("/workspaces/java-nested-jwt/assets/signature.crt"));
        } catch (IOException e1) {
            e1.printStackTrace();
        }
        X509Certificate signatureCert = X509CertUtils.parse(signatureCertByte);

        PublicKey signaturePublicKey = signatureCert.getPublicKey();

        byte[] encryptionCertByte = new byte[0];
        try {
            encryptionCertByte = Files.readAllBytes(Paths.get("/workspaces/java-nested-jwt/assets/encryption.crt"));
        } catch (IOException e1) {
            e1.printStackTrace();
        }
        X509Certificate encryptionCert = X509CertUtils.parse(encryptionCertByte);

        PublicKey encryptionPublicKey = encryptionCert.getPublicKey();

        byte[] fileContent = new byte[0];

        try {
            fileContent = Files.readAllBytes(Paths.get("/workspaces/java-nested-jwt/assets/content-file.txt"));
        } catch (IOException e) {
            e.printStackTrace();
        }

        String fileContentString = Base64.getEncoder().encodeToString(fileContent);

        byte[] signatureKeyByte = new byte[0];
        ;

        try {
            signatureKeyByte = Files.readAllBytes(Paths.get("/workspaces/java-nested-jwt/assets/signature.key"));
        } catch (IOException e) {
            e.printStackTrace();
        }

        String signatureKeyString = new String(signatureKeyByte);

        try {
            RSAKey signatureJwk = JWK.parseFromPEMEncodedObjects(signatureKeyString).toRSAKey();

            JWSSigner signer = new RSASSASigner(signatureJwk);

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signatureJwk.getKeyID()).build(),
                    new JWTClaimsSet.Builder()
                            .subject("Demo")
                            .issueTime(new Date())
                            .issuer("Trustee Name")
                            .claim("content", fileContentString)
                            .claim("fileName", "file_name.csv")
                            .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                            .build());

            signedJWT.sign(signer);

            Gson gson = new GsonBuilder().setPrettyPrinting().create();

            System.out.println(signedJWT.serialize());

            JWEObject jweObject = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                            .contentType("JWT")
                            .build(),
                    new Payload(signedJWT));

            RSAKey encryptionJWK = RSAKey.parse(encryptionCert);

            jweObject.encrypt(new RSAEncrypter(encryptionJWK));

            System.out.println(gson.toJson(jweObject.getHeader()));
            System.out.println(gson.toJson(jweObject.getEncryptedKey()));
            // System.out.println(gson.toJson(jweObject.getIV()));
            // System.out.println(gson.toJson(jweObject.getState()));
            // System.out.println(gson.toJson(jweObject.getPayload()));
            // System.out.println(gson.toJson(jweObject.serialize()));

            String jweString = jweObject.serialize();

            return jweString;
        } catch (JOSEException e) {
            e.printStackTrace();
        }

        return "end";
    }
}
