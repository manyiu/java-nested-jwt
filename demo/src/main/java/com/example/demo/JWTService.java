package com.example.demo;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;
import com.nimbusds.jose.util.X509CertUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

public class JWTService {

    public static String signAndEncrypt() throws IOException {
        byte[] signatureCertByte = Files.readAllBytes(Paths.get("/workspaces/java-nested-jwt/assets/signature.crt"));
        X509Certificate signatureCert = X509CertUtils.parse(signatureCertByte);

        if (signatureCert == null) {
            return "no signature cert";
        }

        PublicKey signaturePublicKey = signatureCert.getPublicKey();

        if (signaturePublicKey instanceof RSAPublicKey) {
            return "we got a rsa public key";
        }

        return "something";
    }
}
