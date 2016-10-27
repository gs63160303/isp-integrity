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

                // Data to be added
                final byte[] addition = "&waffle=liege".getBytes("UTF8");

                // old message size (we know this)
                final int oldMessageSize = pt.length + sharedSecret.length;

                // CEIL(oldMessage + 8 bytes [for length] + 1 byte [for 0x80])
                final int numBlocks = (int) Math.ceil((oldMessageSize + 9.0) / 64.0);

                // Compute the tag with additional data
                final ModifiedSHA1 mySHA = new ModifiedSHA1();
                mySHA.setState(tag, numBlocks);
                mySHA.update(addition);
                final byte[] newTag = mySHA.digest();

                print("newTag  = %s", hex(newTag));

                // create a new PT; size = original [multiple of blocks] + addition - secret
                final byte[] newPt = new byte[ModifiedSHA1.BLOCK_SIZE * numBlocks + addition.length - sharedSecret.length];
                int offset = 0;

                // copy original PT to the newPT
                System.arraycopy(pt, 0, newPt, offset, pt.length);
                offset += pt.length;

                // recreate the original padding (without length)
                final int paddingLength = ModifiedSHA1.BLOCK_SIZE * numBlocks - pt.length - sharedSecret.length - 8;
                System.arraycopy(ModifiedSHA1.PADDING, 0, newPt, offset, paddingLength);
                offset += paddingLength;

                // add the length part of padding
                // the length has to be in bits!
                // format: 8 bytes (Java long) in big endian!
                // detail: https://tools.ietf.org/html/rfc3174#page-4
                final ByteBuffer buffer = ByteBuffer.allocate(8);
                buffer.order(ByteOrder.BIG_ENDIAN);
                buffer.putLong(oldMessageSize * 8);
                final byte[] messageSizeBytes = buffer.array();
                System.arraycopy(messageSizeBytes, 0, newPt, offset, messageSizeBytes.length);
                offset += messageSizeBytes.length;

                // add the addition
                System.arraycopy(addition, 0, newPt, offset, addition.length);

                print("newData = %s", new String(newPt, "UTF-8"));

                outgoing.put(newPt);
                outgoing.put(newTag);
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
