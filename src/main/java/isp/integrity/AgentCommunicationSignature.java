package isp.integrity;

import java.security.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Logger;

/*
 * An agent communication example. The authenticity and integrity of messages
 * are provided with the use of digital signatures.
 * <p/>
 * Additionally, since the signing key (private key) is owned only by the signee,
 * we can be certain that valid signature can only be provided by that party. This
 * provides an additional property called non-repudiation.
 */
public class AgentCommunicationSignature {
    private final static Logger LOG = Logger.getLogger(AgentCommunicationHMAC.class.getCanonicalName());

    public static void main(String[] args) throws NoSuchAlgorithmException {

        /*
         * STEP 1.
         * Alice creates public and private key. Bob receives her public key.
         */
        final KeyPair keyPairAlice = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final PublicKey pkAlice = keyPairAlice.getPublic();
        final PrivateKey skAlice = keyPairAlice.getPrivate();

        /*
         * STEP 2.
         * Setup an insecure communication channel.
         */
        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue<>();

        /*
         * STEP 3 Alice:
         * - uses private key to sign message.
         * - sends a 2-part message:
         *   * message
         *   * signature
         */
        final Agent alice = new Agent("alice", bob2alice, alice2bob, skAlice, "SHA256withRSA") {

            @Override
            public void execute() throws Exception {
                /*
                 * STEP 3.1
                 * Alice writes a message and sends to Bob.
                 */
                final String text = "I love you Bob. Kisses, Alice.";
                outgoing.put(text.getBytes("UTF-8"));

                /*
                 * TODO STEP 3.2
                 * In addition, Alice signs message using selected
                 * algorithm and her private key.
                 */

                final Signature rsa = Signature.getInstance(cipher);
                rsa.initSign((PrivateKey) cipherKey);
                rsa.update(text.getBytes("UTF-8"));
                final byte[] signature = rsa.sign();
                outgoing.put(signature);

            }
        };

        /*
         * STEP 4. Bob :
         * - receives a 2-part message:
         *   * message
         *   * Signature
         * - uses Alice's public key to verify message authenticity and integrity.
         */
        final Agent bob = new Agent("bob", alice2bob, bob2alice, pkAlice, "SHA256withRSA") {
            @Override
            public void execute() throws Exception {
                /*
                 * STEP 4.1
                 * Bob receives the message from Alice.
                 */
                final byte[] pt = incoming.take();
                final String m = new String(pt, "UTF-8");
                print("Received: %s (%s)", m, hex(pt));

                /*
                 * TODO STEP 4.2
                 * Bob setups signature verification. He has to provide
                 * received text and Alice's public key.
                 */
                final Signature rsa = Signature.getInstance(cipher);
                rsa.initVerify((PublicKey) cipherKey);
                rsa.update(pt);

                /*
                 * TODO: STEP 4.3
                 * Bob verifies Alice's signature.
                 */
                if (rsa.verify(incoming.take()))
                    print("Signature OK");
                else
                    print("Invalid signature");

            }
        };

        bob.start();
        alice.start();
    }
}