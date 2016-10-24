package isp.integrity;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.security.*;

public class SignatureExample {
    public static void main(String[] args)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {

        // The message we want to sign
        final String text = "We would like to provide data integrity.";

        /**
         * STEP 1.
         * We create a public-private key pair using standard algorithm names
         * http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
         */
        final KeyPair key = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        /**
         * Alice creates Signature object defining Signature algorithm.
         */
        final Signature rsaAlice = Signature.getInstance("SHA256withRSA");

        /**
         * We initialize the signature object with
         * - Operation modes (SIGN) and
         * - provides appropriate ***Private*** Key
         */
        rsaAlice.initSign(key.getPrivate());

        // Finally, we load the message into the signature object and sign it
        rsaAlice.update(text.getBytes("UTF-8"));
        final byte[] signedText = rsaAlice.sign();
        System.out.println("Signature: " + DatatypeConverter.printHexBinary(signedText));

        /**
         * To verify the signature, we create another signature object
         * and specify its algorithm
         */
        final Signature rsaBob = Signature.getInstance("SHA256withRSA");

        /**
         * We have to initialize it with the mode. But to verify the algorithm,
         * we only need the public key of the original signee
         */
        rsaBob.initVerify(key.getPublic());

        // Check whether the signature is valid
        rsaBob.update(text.getBytes("UTF-8"));

        if (rsaBob.verify(signedText))
            System.out.println("Valid signature.");
        else
            System.err.println("Invalid signature.");
    }
}
