package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * TASK: Assuming Alice and Bob know a shared secret key, secure the channel
 * using a AES in GCM. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be used for AES in GCM.
         */
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final int numberOfRepetitions = 10;

        final Environment env = new Environment();

        env.add(new Agent("alice") {

            private void sendToBob(String message) throws NoSuchAlgorithmException, NoSuchPaddingException,
                    InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                print("MSG: %s%n", message);
                print("PT:  %s%n", Agent.hex(pt));

                final Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
                encrypt.init(Cipher.ENCRYPT_MODE, key);
                final byte[] ct = encrypt.doFinal(pt);
                print("CT:  %s%n", Agent.hex(ct));

                final byte[] iv = encrypt.getIV();
                print("IV:  %s%n", Agent.hex(iv));

                send("bob", ct);
                send("bob", iv);
            }

            private String receiveFromBob() throws InvalidKeyException, InvalidAlgorithmParameterException,
                    NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
                final byte[] ct = receive("bob");
                final byte[] iv = receive("bob");
                print("CT RCVD:  %s%n", Agent.hex(ct));
                print("IV RCVD:  %s%n", Agent.hex(iv));

                final Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
                // the length of the MAC tag is either 128, 120, 112, 104 or 96 bits
                // the default is 128 bits
                final GCMParameterSpec specs = new GCMParameterSpec(128, iv);
                decrypt.init(Cipher.DECRYPT_MODE, key, specs);
                final byte[] pt = decrypt.doFinal(ct);
                print("PT RCVD:  %s%n", Agent.hex(pt));
                print("MSG RCVD: %s%n", new String(pt, StandardCharsets.UTF_8));

                return new String(pt, StandardCharsets.UTF_8);
            }
            
            @Override
            public void task() throws Exception {
                for (int i = 0; i < numberOfRepetitions; i++) {
                    sendToBob("I hope you get this message intact and in secret. Kisses, Alice.");
                    receiveFromBob();
                }
            }
        });

        env.add(new Agent("bob") {

            private void sendToAlice(String message) throws NoSuchAlgorithmException, NoSuchPaddingException,
                    InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                print("MSG: %s%n", message);
                print("PT:  %s%n", Agent.hex(pt));

                final Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
                encrypt.init(Cipher.ENCRYPT_MODE, key);
                final byte[] ct = encrypt.doFinal(pt);
                print("CT:  %s%n", Agent.hex(ct));

                final byte[] iv = encrypt.getIV();
                print("IV:  %s%n", Agent.hex(iv));

                send("alice", ct);
                send("alice", iv);
            }

            private String receiveFromAlice() throws InvalidKeyException, InvalidAlgorithmParameterException,
                    NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
                final byte[] ct = receive("alice");
                final byte[] iv = receive("alice");
                print("CT RCVD:  %s%n", Agent.hex(ct));
                print("IV RCVD:  %s%n", Agent.hex(iv));

                final Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
                // the length of the MAC tag is either 128, 120, 112, 104 or 96 bits
                // the default is 128 bits
                final GCMParameterSpec specs = new GCMParameterSpec(128, iv);
                decrypt.init(Cipher.DECRYPT_MODE, key, specs);
                final byte[] pt = decrypt.doFinal(ct);
                print("PT RCVD:  %s%n", Agent.hex(pt));
                print("MSG RCVD: %s%n", new String(pt, StandardCharsets.UTF_8));

                return new String(pt, StandardCharsets.UTF_8);
            }

            @Override
            public void task() throws Exception {
                for (int i = 0; i < numberOfRepetitions; i++) {
                    receiveFromAlice();
                    sendToAlice("I got your message intact. Kisses, Bob.");
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
