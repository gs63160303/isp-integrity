package isp.integrity;

import sun.security.provider.SHA;

import javax.xml.bind.DatatypeConverter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.Arrays;

public class LEA {

    private static class MySHA1 {
        public final static int BLOCK_SIZE = 64;
        public final static byte[] PADDING = new byte[136];

        static {
            PADDING[0] = (byte) 0x80;
        }

        final SHA alg = new SHA();

        void reset() {
            try {
                final Method m = alg.getClass().getSuperclass().getDeclaredMethod("engineReset");
                m.setAccessible(true);
                m.invoke(alg);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        void update(byte[] bytes) {
            try {
                final Method m = alg.getClass().getSuperclass().getDeclaredMethod(
                        "engineUpdate", byte[].class, int.class, int.class);
                m.setAccessible(true);
                m.invoke(alg, bytes, 0, bytes.length);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        byte[] digest() {
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
            final ByteBuffer buffer = ByteBuffer.wrap(state);
            final int[] stateAsInt = {buffer.getInt(0), buffer.getInt(4),
                    buffer.getInt(8), buffer.getInt(12), buffer.getInt(16)
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
                processedField.set(alg, BLOCK_SIZE);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) throws Exception {
        // Initial data
        final byte[] secret = "NoNeedToRecoverKey".getBytes("UTF-8");
        final byte[] message = "SecuredResource".getBytes("UTF8");
        final MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(secret);
        sha1.update(message);
        final byte[] mac = sha1.digest();
        System.out.println("Original MAC  : " + hex(mac));

        // Data to be added
        final int messageSize = message.length + secret.length;
        final byte[] addition = "TheResourceRemainsUnsecured".getBytes("UTF8");
        
        final MySHA1 mySHA = new MySHA1();
        mySHA.setState(mac);
        mySHA.update(addition);
        final byte[] newMac = mySHA.digest();
        System.out.println("New MAC  : " + hex(newMac));

        final byte[] newMessage = new byte[MySHA1.BLOCK_SIZE - secret.length + addition.length];
        int offset = 0;

        // original message
        System.arraycopy(message, 0, newMessage, offset, message.length);
        offset += message.length;

        // original padding (without length)
        final int oldPaddingLength = MySHA1.BLOCK_SIZE - message.length - secret.length - 8;
        System.arraycopy(MySHA1.PADDING, 0, newMessage, offset, oldPaddingLength);
        offset += oldPaddingLength;

        // padding (length; in bits; use 8 bytes, big endian)
        final ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.putLong(messageSize * 8); // has to be in bits
        final byte[] messageSizeBytes = buffer.array();

        System.arraycopy(messageSizeBytes, 0, newMessage, offset, messageSizeBytes.length);
        offset += messageSizeBytes.length;

        // add extension
        System.arraycopy(addition, 0, newMessage, offset, addition.length);

        if (checkMAC(newMac, newMessage, secret)) {
            System.out.println("==> original      : " + hex(message));
            System.out.println("==> new message   : " + hex(newMessage));
            System.out.println(new String(newMessage, "UTF-8"));
            System.out.println("==> Padding Length: " + oldPaddingLength);
            System.out.println("==> Secret Length : " + (MySHA1.BLOCK_SIZE - message.length - oldPaddingLength - 8));
        } else {
            System.err.println("MAC INVALID");
        }
    }

    private static boolean checkMAC(byte[] mac, byte[] message, byte[] secret) throws Exception {
        final MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(secret);
        md.update(message);
        final byte[] withSecret = md.digest();
        return Arrays.equals(mac, withSecret);
    }

    private static String hex(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }
}
