"""
public class Rizz {
    private static String IV = "W644i2IVQjBBeth9";
    private static String KEY_STRING = "zsfuxwCqcUOfaXNhHxYvJfPIOEoPMiyL";
    private static String RIZZ = "D7NQV/ledSLBd0zF11CPuPAz8y6D8kt/rQ4j5vNOWhFrlwjMsb40Hg4pEhoeVf3s";

    public static boolean do_you_have_rizz(String str) {
        return encrypt(str).equals(RIZZ);
    }

    public static String encrypt(String str) {
        try {
            byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
            SecretKeySpec secretKeySpec = new SecretKeySpec(KEY_STRING.getBytes(), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes());
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            cipher.init(1, secretKeySpec, ivParameterSpec);
            return Base64.encodeToString(cipher.doFinal(bytes), 2);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }
}
"""
from base64 import b64decode
from Crypto.Cipher import AES
IV = b"W644i2IVQjBBeth9"
KEY_STRING = b"zsfuxwCqcUOfaXNhHxYvJfPIOEoPMiyL"
RIZZ = b64decode(b"D7NQV/ledSLBd0zF11CPuPAz8y6D8kt/rQ4j5vNOWhFrlwjMsb40Hg4pEhoeVf3s")

cipher = AES.new(key=KEY_STRING, iv=IV, mode=AES.MODE_CBC)
print(cipher.decrypt(RIZZ)) # b'grey{skibidi_toilet_W_level_500_gyatt_rizz}\x05\x05\x05\x05\x05'
