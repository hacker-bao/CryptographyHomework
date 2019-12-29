package RSAUtil;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import javax.crypto.Cipher;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;


public class RSATest {


    public static void main(String[] args) {

        try {
            System.out.println("请输入原文：");
            Scanner in = new Scanner(System.in);
            String str = in.next();
            System.out.println("原文：" + str);

            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(1024);
            KeyPair key = keyPairGen.generateKeyPair();
            PublicKey publicKey = key.getPublic();
            PrivateKey privateKey = key.getPrivate();

            long startTime = System.currentTimeMillis();
            String inputStr = encrypt(str, new BASE64Encoder().encodeBuffer(publicKey.getEncoded()));
            long secondTime = System.currentTimeMillis();
            long encryptTime = secondTime - startTime;
            System.out.println("密文：" + inputStr + '\n' + "加密所用时间：" + encryptTime + "ms");
            String plain = decrypt(inputStr, new BASE64Encoder().encodeBuffer(privateKey.getEncoded()));
            long endTime = System.currentTimeMillis();
            long decryptTime = endTime - secondTime;
            System.out.println("解密后信息：" + plain + '\n' + "解密所用时间：" + decryptTime + "ms");


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 通过公钥byte[]将公钥还原
    public static PublicKey getPublicKey(byte[] keyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    //通过私钥byte[]将密钥还原
    public static PrivateKey getPrivateKey(byte[] keyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    // 使用N、E值还原公钥
    public static PublicKey getPublicKeyByN_E(String N, String E) throws NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger bigN = new BigInteger(N);
        BigInteger bigE = new BigInteger(E);
        RSAPublicKeySpec spec = new RSAPublicKeySpec(bigN, bigE);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

    // 使用N、D值还原公钥
    public static PrivateKey getPrivateKeyByN_D(String N, String D) throws NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger bigN = new BigInteger(N);
        BigInteger bigD = new BigInteger(D);
        RSAPrivateKeySpec spec = new RSAPrivateKeySpec(bigN, bigD);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePrivate(spec);
    }

    //加密
    public static String encrypt(String str, String publicKey) throws Exception {
        //base64编码的公钥
        byte[] decoded = new BASE64Decoder().decodeBuffer(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);

        //RSA加密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        String outStr = new BASE64Encoder().encode(cipher.doFinal(str.getBytes("UTF-8")));
        return outStr;

    }

    //解密
    public static String decrypt(String str, String privateKey) throws Exception {

        //64位解码加密后的字符串
        byte[] inputStr = new BASE64Decoder().decodeBuffer(new String(str.getBytes("utf-8"), "utf-8"));
        //base64解码的私钥
        byte[] decode = new BASE64Decoder().decodeBuffer(privateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decode);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        String outStr = new String(cipher.doFinal(inputStr));
        return outStr;
    }
}
