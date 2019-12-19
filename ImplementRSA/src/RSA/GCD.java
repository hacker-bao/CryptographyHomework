package RSA;

import java.math.BigInteger;

public class GCD {

    //扩展欧几里得算法
    public static BigInteger[] extGcd(BigInteger a, BigInteger b){
        if(b.equals(BigInteger.ZERO)){
            BigInteger x1 = BigInteger.ONE;
            BigInteger y1 = BigInteger.ZERO;
            return new BigInteger[]{a, x1, y1};
        }else{
            BigInteger[] temp = extGcd(b, a.mod(b));
            BigInteger r  = temp[0];
            BigInteger x1 = temp[1];
            BigInteger y1 = temp[2];

            BigInteger x = y1;
            BigInteger y = x1.subtract(a.divide(b).multiply(y1));
            return new BigInteger[]{r, x, y};
        }
    }
}
