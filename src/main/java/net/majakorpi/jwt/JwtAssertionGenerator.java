package net.majakorpi.jwt;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import picocli.CommandLine;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.Callable;

public class JwtAssertionGenerator implements Callable<Integer> {

    @CommandLine.Option(names = {"-i", "--issuer"}, description = "Token issuer", required = true)
    private String issuer = null;

    @CommandLine.Option(names = {"-a", "--audience"}, description = "Token audience", required = true)
    private String audience = null;

    @CommandLine.Option(names = {"-s", "--subject"}, description = "Token subject", required = true)
    private String subject = null;

    @CommandLine.Option(names = {"-v", "--validity"}, description = "Token validity in seconds (default 3600)")
    private Integer validitySeconds = 3600;

    @CommandLine.Option(names = {"-k", "--key"}, description = "Path to PKCS8 private signing key", required = true)
    private File keyFile = null;

    @CommandLine.Option(names = {"--verbose"}, description = "Output token payload without base64 encoding")
    private Boolean verbose = false;

    private Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

    private static final String UTF_8 = "UTF-8";
    private static final String DOT = ".";
    private static final String HEADER = "{\"alg\":\"RS256\"}";
    private static final String BODY_TEMPLATE =
            "{\"iss\": \"%s\", \"sub\": \"%s\", \"aud\": \"%s\", \"exp\": %s, \"jti\": \"%s\"}";

    public static void main(String... args) throws Exception {
        int exitCode = new CommandLine(new JwtAssertionGenerator()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        StringBuilder token = new StringBuilder();

        try {
            // Prepare claims
            Long exp = (System.currentTimeMillis() / 1000) + validitySeconds;
            String jti = UUID.randomUUID().toString();
            String payload = String.format(BODY_TEMPLATE, issuer, subject, audience, exp, jti);

            if (verbose) {
                System.out.println(payload);
                Gson gson = new GsonBuilder().setPrettyPrinting().create();
                JsonElement je = JsonParser.parseString(payload);
                String prettyJsonString = gson.toJson(je);
                System.out.println(String.format("Token payload:\n%s\n", prettyJsonString));
            }

            // Build token
            token.append(encoder.encodeToString(HEADER.getBytes(UTF_8)))
                    .append(DOT)
                    .append(encoder.encodeToString(payload.getBytes(UTF_8)));
            String headerAndPayload = token.toString();
            token.append(DOT)
                    .append(encoder.encodeToString(signPayload(headerAndPayload)));

            System.out.println(token.toString());
            return 0;
        } catch (Exception e) {
            e.printStackTrace();
            return 1;
        }
    }

    private byte[] signPayload(String payload) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
            InvalidKeyException, SignatureException {
        PrivateKey privateKey = getPrivateKey(keyFile);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(payload.getBytes(UTF_8));
        return signature.sign();
    }

    private PrivateKey getPrivateKey(File keyFile) throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException {
        byte[] keyBytes = Files.readAllBytes(keyFile.toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(spec);
        return privateKey;
    }
}
