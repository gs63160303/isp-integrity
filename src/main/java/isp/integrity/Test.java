package isp.integrity;

import sun.security.provider.SHA;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Test {

    public static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    public static void print(String s, Object... o) {
        System.out.printf(s, o);
        System.out.println();
    }

    public static String hex(byte[] in) {
        return DatatypeConverter.printHexBinary(in);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException, NoSuchMethodException, InvocationTargetException, IllegalAccessException, NoSuchFieldException {
        final String secret = "secretsecret22";
        final String m = "count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo";

        final MessageDigest d = MessageDigest.getInstance("SHA-1");
        d.update(secret.getBytes());
        final byte[] tag = d.digest(m.getBytes());

        print("pt      = %s", hex(m.getBytes()));
        print("tag     = %s", hex(tag));

        // mitm
        final byte[] padding = new byte[]{
                (byte) 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0x45//0x02, 0x28
        };
        final byte[] suffix = "&waffle=liege".getBytes("UTF-8");
        final byte[] newPt = concat(concat(m.getBytes(), padding), suffix);

        final SHA sha = new SHA();


        Field f = sha.getClass().getDeclaredField("state"); //NoSuchFieldException
        f.setAccessible(true);
        int[] initialState = (int[]) f.get(sha);

        System.out.println(tag.length);
        System.out.println(initialState.length);

        for (int i = 0; i < tag.length; i++) {
            initialState[i] = tag[i];
        }

        final Method engineUpdate = sha.getClass().getSuperclass().getDeclaredMethod("engineUpdate", byte.class);
        engineUpdate.setAccessible(true);

        for (byte b : suffix) {
            engineUpdate.invoke(sha, b);
        }

        final Method engineDigest = sha.getClass().getSuperclass().getDeclaredMethod("engineDigest");
        engineDigest.setAccessible(true);
        final byte[] newTag = (byte[]) engineDigest.invoke(sha);

        //d.update(tag);
        // final byte[] newTag = d.digest(suffix);

        print("newPt   = %s", hex(newPt));
        print("newTag  = %s", hex(newTag));

        // verifier
        d.update(secret.getBytes());
        final byte[] tagComputed = d.digest(newPt);
        print("tag_c   = %s", hex(tagComputed));

        if (Arrays.equals(newTag, tagComputed))
            print("Authenticity and integrity verified.");
        else
            print("Failed to verify authenticity and integrity.");

    }
}
