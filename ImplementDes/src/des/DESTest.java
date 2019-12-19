package des;

import java.util.Scanner;

public class DESTest {
    public static void main(String[] args) {
        Scanner in = new Scanner(System.in);
        System.out.println("请输入原文:");
        String origin = in.next();
        System.out.println("请输入秘钥：");
        String key = in.next();
        System.out.println("原文："+origin);
        DES des = new DES(key, origin);
//        double startTime = System.nanoTime();
        long startTime = System.currentTimeMillis();
        byte[] c = des.deal(origin.getBytes(),1);
        StringBuilder s = new StringBuilder();
        for(int i = 0; i < c.length; i++){
            s.append(Integer.toHexString(c[i] & 0xff));
        }
//        double secondTime = System.nanoTime();
//        double encryptTime = secondTime - startTime;
        long secondTime = System.currentTimeMillis();
        long encryptTime = secondTime - startTime;
        System.out.println("密文：" + s + "\n加密所需时间： " + encryptTime + "ms");
        byte[] p = des.deal(c,0);
//        double endTime = System.nanoTime();
//        double decryptTime = endTime - secondTime;
        long endTime = System.currentTimeMillis();
        long decryptTime = endTime - secondTime;
        System.out.println("解密后信息："+new String(p) + '\n' + "解密所用时间：" + decryptTime + "ms");
    }
}
