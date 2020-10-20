package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, provide integrity to the channel
 * using HMAC implemted with SHA256. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        final int numberOfRepetitions = 10;

        final Environment env = new Environment();

        env.add(new Agent("alice") {

            private String receiveFromBob() throws ManInTheMiddleException, NoSuchAlgorithmException,
                    InvalidKeyException {
                final byte[] plaintext = receive("bob");
                final byte[] tag = receive("bob");

                final Mac alice = Mac.getInstance("HmacSHA256");
                alice.init(key);

                final byte[] tagToVerify = alice.doFinal(plaintext);
                final boolean ok = verify(tag, tagToVerify, key);

                if (ok) {
                    return new String(plaintext);
                } else {
                    throw new ManInTheMiddleException();
                }
            }

            private void sendToBob(final String message) throws NoSuchAlgorithmException, InvalidKeyException {
                final byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);

                final Mac alice = Mac.getInstance("HmacSHA256");
                alice.init(key);
                final byte[] tag = alice.doFinal(plaintext);
                final String messageHmacAsString = Agent.hex(tag);
                System.out.println("HMAC: " + messageHmacAsString);

                send("bob", plaintext);
                send("bob", tag);
            }

            @Override
            public void task() throws Exception {
                for (int i = 1; i <= numberOfRepetitions; i++) {
                    sendToBob("I hope you get this message intact. Kisses, Alice.");
                    try {
                        final String receivedMessage = receiveFromBob();
                        System.out.printf("Received from Bob: %s\n", receivedMessage);
                    } catch (ManInTheMiddleException e) {
                        System.out.println("I'm starting with the man in the middle ...");
                    }
                }
            }
        });

        env.add(new Agent("bob") {

            private String receiveFromAlice() throws ManInTheMiddleException, NoSuchAlgorithmException,
                    InvalidKeyException {
                final byte[] plaintext = receive("alice");
                final byte[] tag = receive("alice");

                final Mac bob = Mac.getInstance("HmacSHA256");
                bob.init(key);

                final byte[] tagToVerify = bob.doFinal(plaintext);
                final boolean ok = verify(tag, tagToVerify, key);

                if (ok) {
                    return new String(plaintext);
                } else {
                    throw new ManInTheMiddleException();
                }
            }

            private void sendToAlice(final String message) throws NoSuchAlgorithmException, InvalidKeyException {
                final byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);

                final Mac bob = Mac.getInstance("HmacSHA256");
                bob.init(key);
                final byte[] tag = bob.doFinal(plaintext);
                final String messageHmacAsString = Agent.hex(tag);
                System.out.println("HMAC: " + messageHmacAsString);

                send("alice", plaintext);
                send("alice", tag);
            }

            @Override
            public void task() throws Exception {
                for (int i = 1; i <= numberOfRepetitions; i++) {
                    try {
                        final String receivedMessage = receiveFromAlice();
                        System.out.printf("Received from Alice: %s\n", receivedMessage);
                        sendToAlice("I got your message intact. Kisses; Bob.");
                    } catch (ManInTheMiddleException e) {
                        sendToAlice("Huston, we've got a man in the middle!");
                    }
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }

    public static boolean verify(byte[] tag1, byte[] tag2, Key key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        /*
            FIXME: Defense #2

            The idea is to hide which bytes are actually being compared
            by MAC-ing the tags once more and then comparing those tags
         */
        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        final byte[] tagtag1 = mac.doFinal(tag1);
        final byte[] tagtag2 = mac.doFinal(tag2);

        return Arrays.equals(tagtag1, tagtag2);
    }

    static class ManInTheMiddleException extends Exception {

        /**
         *
         */
        private static final long serialVersionUID = 1L;

    }
}
