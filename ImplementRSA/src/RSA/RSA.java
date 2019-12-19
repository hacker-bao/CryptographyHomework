package RSA;

import java.math.BigInteger;

public class RSA {

    //生成密钥
    public BigInteger[][] genKey(BigInteger p, BigInteger q){
        BigInteger n = p.multiply(q);
        //计算n的欧拉函数m
        BigInteger m = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger e = new BigInteger("4007");

        BigInteger[] exGcdResult = GCD.extGcd(e, m);
        BigInteger d = exGcdResult[1];
        //若产生的d为负数，将负逆元转正
        if(d.max(BigInteger.ZERO).equals(BigInteger.ZERO)){
            d = d.add(m);
        }

        //返回密钥{n, e}为公钥，{n, d}为私钥
        return new BigInteger[][]{{n, e}, {n ,d}};
    }

    //加密
    public BigInteger encrypt(BigInteger m, BigInteger[] pubKey){
        BigInteger n = pubKey[0];
        BigInteger e = pubKey[1];

        return new Exponentiation().expMode(m, e, n);
    }

    //解密
    public BigInteger decrypt(BigInteger c, BigInteger[] selfKey){
        BigInteger n = selfKey[0];
        BigInteger d = selfKey[1];

        return new Exponentiation().expMode(c, d, n);
    }

    //字符串转换二进制数表示
    public BigInteger stringToBinary(byte[] a){
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : a) {
            StringBuilder s = new StringBuilder(Integer.toBinaryString(b & 0xff));
            while (s.length() < 8) {
                s.insert(0, '0');
            }
            stringBuilder.append(s);
        }
        return new BigInteger(stringBuilder.toString());
    }

    //二进制转换为字符串
    public String binaryToString(BigInteger d){
        StringBuilder sb = new StringBuilder(d.toString());
        if(sb.length() % 8 != 0){
            for(int i = 0; i <= sb.length() % 8; i++) {
                sb.insert(i, '0');
            }
        }
        byte[] bts = new byte[sb.length() / 8];

        for (int i = 0; i < bts.length; i++)
            bts[i] = (byte) Integer.parseInt(sb.substring(i * 8, i * 8 + 8), 2);

        return new String(bts);
    }
}

