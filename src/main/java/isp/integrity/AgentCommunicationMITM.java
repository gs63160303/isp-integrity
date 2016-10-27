package isp.integrity;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * As the man (or a woman) in the middle (MITM), intercept a message from Alice,
 * modify parameters as instructed, and create a tag that will successfully verify.
 * <p>
 * Useful resources:
 * - SHA-1 RFC https://tools.ietf.org/html/rfc3174 (section o padding in particular)
 * - Wikipedia entry: https://en.wikipedia.org/wiki/Length_extension_attack
 * <p>
 * You can assume to know the length of the plaintext and the length of the secret that is used
 * for MAC-ing.
 * <p>
 * To manually set the internal state of the SHA-1 algorithm, use the {@link ModifiedSHA1} class.
 */
public class AgentCommunicationMITM {

    public static void main(String[] args) throws Exception {
        // secret shared between client1 and the service
        final byte[] sharedSecret = "secretsecret22".getBytes("UTF-8");

        final BlockingQueue<byte[]> alice2mitm = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> mitm2service = new LinkedBlockingQueue<>();

        final Agent client = new Agent("CLIENT 1", alice2mitm, null, null, "SHA-1") {
            @Override
            public void execute() throws Exception {
                final String message = "count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo";
                final byte[] pt = message.getBytes("UTF-8");

                final MessageDigest d = MessageDigest.getInstance(cipher);
                d.update(sharedSecret);
                d.update(pt);
                final byte[] tag = d.digest();

                print("data = %s", message);
                print("pt   = %s", hex(pt));
                print("tag  = %s", hex(tag));

                outgoing.put(pt);
                outgoing.put(tag);
            }
        };

        final Agent mitm = new Agent("MITM", mitm2service, alice2mitm, null, null) {
            @Override
            public void execute() throws Exception {
                final byte[] pt = incoming.take();
                final byte[] tag = incoming.take();
                final String message = new String(pt, "UTF-8");
                print("data    = %s", message);
                print("pt      = %s", hex(pt));
                print("tag     = %s", hex(tag));

                // TODO: manipulate the parameters and send another valid request
                // You can assume that when the parameters repeat, the service uses the right-most value
                // For instance, to change the name of the waffle, you could send the following request
                //     count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo&waffle=liege
                // You can also assume to know the length of the secret

                outgoing.put(pt);
                outgoing.put(tag);
            }
        };

        final Agent service = new Agent("SERVICE", null, mitm2service, null, "SHA-1") {
            @Override
            public void execute() throws Exception {
                final byte[] pt = incoming.take();
                final byte[] tag = incoming.take();

                // recompute the tag
                final MessageDigest d = MessageDigest.getInstance(cipher);
                d.update(sharedSecret);
                d.update(pt);
                final byte[] tagComputed = d.digest();

                print("data   = %s", new String(pt, "UTF-8"));
                print("pt     = %s", hex(pt));

                if (Arrays.equals(tag, tagComputed))
                    print("MAC verification succeeds: %s == %s", hex(tag), hex(tagComputed));
                else
                    print("MAC verification fails: %s != %s", hex(tag), hex(tagComputed));
            }
        };

        client.start();
        mitm.start();
        service.start();
    }
}
