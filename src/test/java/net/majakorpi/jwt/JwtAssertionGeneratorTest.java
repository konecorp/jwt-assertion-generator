package net.majakorpi.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.ginsberg.junit.exit.ExpectSystemExitWithStatus;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import picocli.CommandLine;

import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

class JwtAssertionGeneratorTest {

    public static final String TESTISSUER = "testissuer";
    public static final String TESTAUDIENCE = "testaudience";
    public static final String TESTSUBJECT = "testsubject";

    @Test
    @ExpectSystemExitWithStatus(0)
    void generateToken() throws Exception {
        URL key = this.getClass().getResource("/private.key.pkcs8");
        JwtAssertionGenerator.main(
                "--audience",
                TESTAUDIENCE,
                "--issuer",
                TESTISSUER,
                "--subject",
                TESTSUBJECT,
                "--key",
                key.getPath()
        );
    }

    @Test
    void generateAndValidate() {
        PrintStream out = System.out;
        try {
            URL key = this.getClass().getResource("/private.key.pkcs8");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            System.setOut(new PrintStream(baos));
            int exitCode = new CommandLine(new JwtAssertionGenerator()).execute(
                    "--audience",
                    TESTAUDIENCE,
                    "--issuer",
                    TESTISSUER,
                    "--subject",
                    TESTSUBJECT,
                    "--key",
                    key.getPath()
            );
            Assertions.assertEquals(0, exitCode);

            String token = baos.toString();
            String[] components = token.split("\\.");

            String header = new String(Base64.getUrlDecoder().decode(components[0]));
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            JsonElement jheader = JsonParser.parseString(header);
            Assertions.assertEquals("RS256", jheader.getAsJsonObject().get("alg").getAsString());

            String body = new String(Base64.getUrlDecoder().decode(components[1]));
            JsonElement jBody = JsonParser.parseString(body);
            Assertions.assertNotNull(jBody.getAsJsonObject().get("jti").getAsString());
            Assertions.assertDoesNotThrow(new Executable() {
                @Override
                public void execute() throws Throwable {
                    UUID.fromString(String.valueOf(jBody.getAsJsonObject().get("jti").getAsString()));
                }
            });

            Assertions.assertDoesNotThrow(new Executable() {
                @Override
                public void execute() throws Throwable {
                    Algorithm algorithm = Algorithm.RSA256(getPublicCert(
                            this.getClass().getResource("/public.crt.pkcs8").getPath()),
                            getPrivateKey(this.getClass().getResource("/private.key.pkcs8").getPath()));
                    JWTVerifier verifier = JWT.require(algorithm)
                            .withIssuer(TESTISSUER)
                            .withAudience(TESTAUDIENCE)
                            .withSubject(TESTSUBJECT)
                            .build();
                    DecodedJWT jwt = verifier.verify(token);
                }
            });

        } finally {
            System.setOut(out);
        }
    }

    @Test
    void generateWithSpecificValidity() {
        PrintStream out = System.out;
        try {
            URL key = this.getClass().getResource("/private.key.pkcs8");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            System.setOut(new PrintStream(baos));
            int exitCode = new CommandLine(new JwtAssertionGenerator()).execute(
                    "--audience",
                    TESTAUDIENCE,
                    "--issuer",
                    TESTISSUER,
                    "--subject",
                    TESTSUBJECT,
                    "--key",
                    key.getPath(),
                    "--validity",
                    "10"
            );
            Assertions.assertEquals(0, exitCode);

            String token = baos.toString();
            Assertions.assertDoesNotThrow(new Executable() {
                @Override
                public void execute() throws Throwable {
                    Algorithm algorithm = Algorithm.RSA256(getPublicCert(
                            this.getClass().getResource("/public.crt.pkcs8").getPath()),
                            getPrivateKey(this.getClass().getResource("/private.key.pkcs8").getPath()));
                    JWTVerifier verifier = JWT.require(algorithm)
                            .withIssuer(TESTISSUER)
                            .withAudience(TESTAUDIENCE)
                            .withSubject(TESTSUBJECT)
                            .build();
                    DecodedJWT jwt = verifier.verify(token);
                    Assertions.assertTrue(jwt.getExpiresAt().before(new Date(System.currentTimeMillis() + 11000)),
                            "Token should expire in 10 seconds");
                }
            });

        } finally {
            System.setOut(out);
        }
    }

    private RSAPrivateKey getPrivateKey(String keyPath) throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(keyPath));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(spec);
        return (RSAPrivateKey) privateKey;
    }

    private RSAPublicKey getPublicCert(String keyPath) throws IOException, CertificateException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream(keyPath);
        X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
        PublicKey key = cer.getPublicKey();
        return (RSAPublicKey) key;
    }
}
