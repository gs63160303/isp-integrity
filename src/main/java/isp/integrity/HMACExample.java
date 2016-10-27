package isp.integrity;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;

public class HMACExample {
    public static void main(String[] args) throws Exception {

        final String message = "We would like to provide data integrity for this message.";

        /**
         * STEP 1.
         * Select HMAC algorithm and get new HMAC object instance.
         * Standard Algorithm Names
         * http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
         */
        final Mac hmacAlgorithm = Mac.getInstance("HmacSHA256");

        /**
         * STEP 1.
         * Alice and Bob agree upon a shared secret session key that will be
         * used for hash based message authentication code.
         */
        final Key hmacKey = KeyGenerator.getInstance("HmacSHA256").generateKey();

        /**
         * STEP 3.
         * Initialize HMAC and provide shared secret session key. Create HMAC message.
         */
        hmacAlgorithm.init(hmacKey);
        final byte[] messageHmac = hmacAlgorithm.doFinal(message.getBytes("UTF-8"));

        /**
         * STEP 4.
         * Print out HMAC.
         */
        final String messageHmacAsString = DatatypeConverter.printHexBinary(messageHmac);
        System.out.println("HMAC: " + messageHmacAsString);
    }

}
