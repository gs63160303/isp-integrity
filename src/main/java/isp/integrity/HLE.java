package isp.integrity;

import sun.security.provider.SHA;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
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

        void engineUpdate(byte[] var1, int var2, int var3) {
            try {
                final Method m = alg.getClass().getSuperclass().getDeclaredMethod(
                        "engineUpdate", byte[].class, int.class, int.class);
                m.setAccessible(true);
                m.invoke(alg, var1, var2, var3);
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
                throw new Error("AAA");
            }
        }

        void setState(int[] state) {
            try {
                final Field f = alg.getClass().getDeclaredField("state");
                f.setAccessible(true);
                f.set(alg, state);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        void setBytesProcessed(long n) {
            try {
                final Field f = alg.getClass().getSuperclass().getDeclaredField("bytesProcessed");
                f.setAccessible(true);
                f.set(alg, n);
            } catch (Exception e) {
                e.printStackTrace();
            }
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
        final byte[] maliciousAddition = "maliciousAddition".getBytes("UTF8");
        final byte[] initialMessage = "initialMessage".getBytes("UTF8");
        final byte[] originalMAC = createMAC(initialMessage);

        System.out.println("Original MAC  : " + hex(originalMAC));

        System.out.println("Recover digest state...");
        SHA1.engineReset();

        // initialize set internal state to the one of the original MAC
        final int[] state = {
                bytesToInt(originalMAC[0], originalMAC[1], originalMAC[2], originalMAC[3]),
                bytesToInt(originalMAC[4], originalMAC[5], originalMAC[6], originalMAC[7]),
                bytesToInt(originalMAC[8], originalMAC[9], originalMAC[10], originalMAC[11]),
                bytesToInt(originalMAC[12], originalMAC[13], originalMAC[14], originalMAC[15]),
                bytesToInt(originalMAC[16], originalMAC[17], originalMAC[18], originalMAC[19])
        };
        SHA1.setState(state);
        SHA1.setBytesProcessed(BLOCK_SIZE);

        System.out.println("Compute MAC for extension ...");
        SHA1.engineUpdate(maliciousAddition, 0, maliciousAddition.length);

        // compute the extended hash
        final byte[] macCandidate = SHA1.engineDigest();
        System.out.println("Extended MAC  : " + hex(macCandidate));

        System.out.println("Trying to find suitable input....");
        // determine the necessary input....
        for (int i = 1; i <= PADDING.length; i++) {
            final byte[] hashInput = new byte[initialMessage.length + i + 8 + maliciousAddition.length];
            int pointer = 0;

            // # add original message
            System.arraycopy(initialMessage, 0, hashInput, pointer, initialMessage.length);
            pointer += initialMessage.length;

            // # add padding
            System.arraycopy(PADDING, 0, hashInput, pointer, i);
            pointer += i;

            // # add length of user data (8 bytes)
            // j is the computed length of the original message in bits
            // (blockSize - padding length - 8 length bytes)
            int j = (BLOCK_SIZE - i - 8) << 3;

            // the first word is 0 in our case, due to only 32 bit int
            hashInput[pointer] = 0;
            hashInput[pointer + 1] = 0;
            hashInput[pointer + 2] = 0;
            hashInput[pointer + 3] = 0;
            hashInput[pointer + 4] = (byte) ((j >>> 24));
            hashInput[pointer + 5] = (byte) ((j >>> 16));
            hashInput[pointer + 6] = (byte) ((j >>> 8));
            hashInput[pointer + 7] = (byte) (j);
            pointer += 8;

            // # add extension
            System.arraycopy(maliciousAddition, 0, hashInput, pointer, maliciousAddition.length);
            //pointer += extension.length;

            // # check guess
            if (isMACCorrect(macCandidate, hashInput)) {
                System.out.println("==> Hash input    : " + hex(hashInput));
                System.out.println("==> Padding Length: " + i);
                System.out.println("==> Secret Length : " + (BLOCK_SIZE - initialMessage.length - i - 8));
                break;
            }
        }
    }

    private static int bytesToInt(byte... bytes) {
        return ((0xFF & bytes[0]) << 24
                | (0xFF & bytes[1]) << 16
                | (0xFF & bytes[2]) << 8
                | (0xFF & bytes[3]));
    }

    private static boolean isMACCorrect(final byte[] macToCheck, final byte[] msg) throws Exception {
        final byte[] referenceHash = createMAC(msg);
        System.out.println("Reference hash: " + hex(referenceHash));
        return Arrays.equals(macToCheck, referenceHash);
    }

    private static String hex(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }

    private static byte[] createMAC(final byte[] msg) throws Exception {
        SHA1.engineReset();
        SHA1.engineUpdate(SECRET, 0, SECRET.length);
        SHA1.engineUpdate(msg, 0, msg.length);
        return SHA1.engineDigest();
    }
}
