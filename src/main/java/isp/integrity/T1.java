package isp.integrity;

import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class T1 {

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

    public static int fromArray(byte[] payload) {
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        return buffer.getInt();
    }

    public static byte[] toArray(int value) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.putInt(value);
        return buffer.array();
    }

    public static void main(String[] args) throws Exception {
        System.out.printf("%d", 0x1b);
    }
}