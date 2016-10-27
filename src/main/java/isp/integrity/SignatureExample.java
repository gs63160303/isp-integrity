package isp.integrity;

import javax.xml.bind.DatatypeConverter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class SignatureExample {
    public static void main(String[] args) throws Exception {

        // The message we want to sign
        final String text = "We would like to provide data integrity.";

        /**
         * STEP 1.
         * We create a public-private key pair.
         * http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
         */
        final KeyPair key = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        /**
         * Alice creates Signature object defining Signature algorithm.
         */
        final Signature signatureAlg = Signature.getInstance("SHA256withRSA");

        /**
         * We initialize the signature object with
         * - Operation modes (SIGN) and
         * - provides appropriate ***Private*** Key
         */
        signatureAlg.initSign(key.getPrivate());

        // Finally, we load the message into the signature object and sign it
        signatureAlg.update(text.getBytes("UTF-8"));
        final byte[] signedText = signatureAlg.sign();
        System.out.println("Signature: " + DatatypeConverter.printHexBinary(signedText));

        /**
         * To verify the signature, we create another signature object
         * and specify its algorithm
         */
        final Signature signatureAlg2 = Signature.getInstance("SHA256withRSA");

        /**
         * We have to initialize it with the mode. But to verify the algorithm,
         * we only need the public key of the original signee
         */
        signatureAlg2.initVerify(key.getPublic());

        //Finally, we can check whether the signature is valid
        signatureAlg2.update(text.getBytes("UTF-8"));

        if (signatureAlg2.verify(signedText))
            System.out.println("Valid signature.");
        else
            System.err.println("Invalid signature.");
    }
}
