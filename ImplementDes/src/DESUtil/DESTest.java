package DESUtil;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class DESTest {

    private static final String ALGORITHM = "DES";
    private static final String TRANSFORMATION = "DES/ECB/PKCS5Padding";

    @SuppressWarnings("unused")
    public static byte[] encrypt(byte[] src,byte[]key)
    {
        try {
            //加密
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(ALGORITHM);
            KeySpec keySpec = new DESKeySpec(key);
            SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey,new SecureRandom());
            byte[] enMsgBytes = cipher.doFinal(src);
            return enMsgBytes;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @SuppressWarnings("unused")
    public static byte[] decrypt(byte[] encryptBytes,byte[]key){
        try {
            Cipher deCipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeyFactory deDecretKeyFactory = SecretKeyFactory.getInstance(ALGORITHM);
            KeySpec deKeySpec = new DESKeySpec(key);
            SecretKey deSecretKey = deDecretKeyFactory.generateSecret(deKeySpec);
            deCipher.init(Cipher.DECRYPT_MODE, deSecretKey,new SecureRandom());
            byte[] deMsgBytes = deCipher.doFinal(encryptBytes);
            return deMsgBytes;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) throws Exception{
        Scanner in = new Scanner(System.in);
        System.out.println("请输入原文:");
        String origin = in.next();
        System.out.println("请输入秘钥：");
        String key = in.next();
        System.out.println("原文："+origin);
        long startTime = System.currentTimeMillis();
        byte[] encryptBytes = DESTest.encrypt(origin.getBytes(), key.getBytes());
        String s = new String(encryptBytes);
        long secondTime = System.currentTimeMillis();
        long encryptTime = secondTime - startTime;
        System.out.println("密文：" + s + "\n加密所需时间： " + encryptTime + "ms");
        byte[] deMsgBytes = DESTest.decrypt(encryptBytes, key.getBytes());
        long endTime = System.currentTimeMillis();
        long decryptTime = endTime - secondTime;
        System.out.println("解密后信息："+new String(deMsgBytes) + '\n' + "解密所用时间：" + decryptTime + "ms");
    }
}