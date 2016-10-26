package isp.integrity;

import sun.security.provider.SHA;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.Arrays;

public class HLE {

    private static class MySHA {
        final SHA alg = new SHA();

        void engineReset() {
            try {
                final Method m = alg.getClass().getSuperclass().getDeclaredMethod("engineReset");
                m.setAccessible(true);
                m.invoke(alg);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        void engineUpdate(byte[] bytes) {
            try {
                final Method m = alg.getClass().getSuperclass().getDeclaredMethod(
                        "engineUpdate", byte[].class, int.class, int.class);
                m.setAccessible(true);
                m.invoke(alg, bytes, 0, bytes.length);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        byte[] engineDigest() {
            try {
                final Method method = alg.getClass().getSuperclass().getDeclaredMethod("engineDigest");
                method.setAccessible(true);
                return (byte[]) method.invoke(alg);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }

        void setState(byte[] state) {
            assert state.length == 20;

            final int[] stateAsInt = {
                    bytesToInt(state[0], state[1], state[2], state[3]),
                    bytesToInt(state[4], state[5], state[6], state[7]),
                    bytesToInt(state[8], state[9], state[10], state[11]),
                    bytesToInt(state[12], state[13], state[14], state[15]),
                    bytesToInt(state[16], state[17], state[18], state[19])
            };

            try {
                // set the initial state of the SHA1
                final Field stateField = alg.getClass().getDeclaredField("state");
                stateField.setAccessible(true);
                stateField.set(alg, stateAsInt);

                // set the number of processed bytes to 64
                // (assuming the original message + padding fits into  one 512-bit block)
                final Field processedField = alg.getClass().getSuperclass().getDeclaredField("bytesProcessed");
                processedField.setAccessible(true);
                processedField.set(alg, 64L);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        int bytesToInt(byte... bytes) {
            return ((0xFF & bytes[0]) << 24
                    | (0xFF & bytes[1]) << 16
                    | (0xFF & bytes[2]) << 8
                    | (0xFF & bytes[3]));
        }

    }

    private static final int BLOCK_SIZE = 64;
    private static final byte[] SECRET;
    private static final byte[] PADDING = new byte[136];
    private static final MySHA SHA1 = new MySHA();

    static {
        try {
            SECRET = "NoNeedToRecoverKey".getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new Error("Should not happen");
        }

        PADDING[0] = (byte) 0x80;
    }

    public static void main(String[] args) throws Exception {
        final byte[] addition = "TheResourceRemainsUnsecured".getBytes("UTF8");
        final byte[] message = "SecuredResource".getBytes("UTF8");
        System.out.println(message.length + SECRET.length);

        final MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(SECRET);
        sha1.update(message);
        final byte[] mac = sha1.digest();

        System.out.println("Original MAC  : " + hex(mac));

        // initialize set internal state to the one of the original MAC
        SHA1.engineReset();
        SHA1.setState(mac);

        System.out.println("Compute MAC for extension ...");
        SHA1.engineUpdate(addition);

        // compute the extended hash
        final byte[] tagCandidate = SHA1.engineDigest();
        System.out.println("Extended MAC  : " + hex(tagCandidate));

        System.out.println("Trying to find suitable input....");
        // determine the necessary input....
        for (int i = 0; i <= PADDING.length; i++) {
            final byte[] newMessage = new byte[message.length + i + 8 + addition.length];
            int offset = 0;

            // add original message
            System.arraycopy(message, 0, newMessage, offset, message.length);
            offset += message.length;

            // add padding
            System.arraycopy(PADDING, 0, newMessage, offset, i);
            offset += i;

            // # add length of user data (8 bytes)
            // j is the computed length of the original message in bits
            // (blockSize - padding length - 8 length bytes)
            //int j = (BLOCK_SIZE - i - 8) * 8; // <- 33

            final int j = (message.length + SECRET.length) * 8;

            final ByteBuffer buffer = ByteBuffer.allocate(8);
            buffer.order(ByteOrder.BIG_ENDIAN);
            buffer.putLong(j);
            final byte[] messageLength = buffer.array();
            System.arraycopy(messageLength, 0, newMessage, offset, messageLength.length);
            offset += messageLength.length;

            // # add extension
            System.arraycopy(addition, 0, newMessage, offset, addition.length);

            if (checkMAC(tagCandidate, newMessage)) {
                System.out.println("==> new message   : " + hex(newMessage));
                System.out.println("==> Padding Length: " + i);
                System.out.println("==> Secret Length : " + (BLOCK_SIZE - message.length - i - 8));
                break;
            }
        }
    }

    private static boolean checkMAC(final byte[] candidateMac, final byte[] message) throws Exception {
        final MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(SECRET);
        md.update(message);
        final byte[] withSecret = md.digest();
        return Arrays.equals(candidateMac, withSecret);
    }

    private static String hex(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }
}
