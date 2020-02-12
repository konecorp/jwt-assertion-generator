import org.apache.commons.codec.binary.Base64;
import java.io .*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security .*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.MessageFormat;

public class JwtAssertionGenerator {
    public static void main(String[] args) {

        String header = "{\"alg\":\"RS256\"}";
        String claimTemplate = "'{'\"iss\": \"{0}\", \"sub\": \"{1}\", \"aud\": \"{2}\", \"exp\": \"{3}\", \"jti\": \"{4}\"'}'";

        try {
            StringBuffer token = new StringBuffer();

            //Encode the JWT Header and add it to our string to sign
            token.append(Base64.encodeBase64URLSafeString(header.getBytes("UTF-8")));

            //Separate with a period
            token.append(".");

            //Create the JWT Claims Object
            String[] claimArray = new String[5];
            claimArray[0] = "your_client_id";
            claimArray[1] = "your_account_id_you_use_to_log_in_to_API_portal";
            claimArray[2] = "your_token_endpoint";
            claimArray[3] = Long.toString( ( System.currentTimeMillis()/1000 ));
            claimArray[4] = Long.toString( ( System.currentTimeMillis()/1000 ) + 30000);

            MessageFormat claims;
            claims = new MessageFormat(claimTemplate);
            String payload = claims.format(claimArray);

            //Add the encoded claims object
            token.append(Base64.encodeBase64URLSafeString(payload.getBytes("UTF-8")));

            //Load the private key from a keystore
//            KeyStore keystore = KeyStore.getInstance("JKS");
//            keystore.load(new FileInputStream("./path/to/keystore.jks"), "keystorepassword".toCharArray());
//            PrivateKey privateKey = (PrivateKey) keystore.getKey("certalias", "privatekeypassword".toCharArray());
            byte[] keyBytes = Files.readAllBytes(Paths.get("/path/to/your/private_key.pkcs8"));
            PKCS8EncodedKeySpec spec =
                    new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(spec);

            //Sign the JWT Header + "." + JWT Claims Object
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(token.toString().getBytes("UTF-8"));
            String signedPayload = Base64.encodeBase64URLSafeString(signature.sign());

            //Separate with a period
            token.append(".");

            //Add the encoded signature
            token.append(signedPayload);

            System.out.println(token.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
