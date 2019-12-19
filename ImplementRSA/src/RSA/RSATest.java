package RSA;

import java.math.BigInteger;
import java.util.Scanner;

public class RSATest {
    public static void main(String[] args) {
        // 公钥私钥中用到的两个大质数p,q
        BigInteger p = new BigInteger("106697219132480173106064317148705638676529121742557567770857687729397446898790451577487723991083173010242416863238099716044775658681981821407922722052778958942891831033512463262741053961681512908218003840408526915629689432111480588966800949428079015682624591636010678691927285321708935076221951173426894836169");
        BigInteger q = new BigInteger("144819424465842307806353672547344125290716753535239658417883828941232509622838692761917211806963011168822281666033695157426515864265527046213326145174398018859056439431422867957079149967592078894410082695714160599647180947207504108618794637872261572262805565517756922288320779308895819726074229154002310375209");

        RSA rsa = new RSA();
        // 生成公钥私钥
        BigInteger[][] keys = rsa.genKey(p, q);
        BigInteger[] pubKey  = keys[0];
        BigInteger[] selfKey = keys[1];

        // 需要被加密的信息转化成数字
        System.out.println("请输入原文：");
        Scanner in = new Scanner(System.in);
        String str = in.next();
        BigInteger m = rsa.stringToBinary(str.getBytes());
        System.out.println("原文：" + str);
        // 信息加密
        long startTime = System.currentTimeMillis();
        BigInteger c = rsa.encrypt(m, pubKey);
        long secondTime = System.currentTimeMillis();
        long encryptTime = secondTime - startTime;
        System.out.println("密文：" + c + '\n' + "加密所用时间：" + encryptTime + "ms");
        // 信息解密
        BigInteger d = rsa.decrypt(c, selfKey);
        long endTime = System.currentTimeMillis();
        long decryptTime = endTime - secondTime;
        String plain = rsa.binaryToString(d);
        System.out.println("解密后信息：" + plain + '\n' + "解密所用时间：" + decryptTime + "ms");
    }
}
