package DES;

public class DES {
    private ReplaceTable replaceTable = new ReplaceTable();
    private int originLength;
    private int p_origin_length;
    private int[][] subKey = new int[16][48];

    public DES(String key, String content){
        p_origin_length = content.getBytes().length;
        generateKeys(key);
    }

    public byte[] deal(byte[] plainBytes, int mode){
        originLength = plainBytes.length;
        //将原文长度填充为64位的整数倍
        int rNum = 8 - originLength % 8;
        byte[] plainPadding;
        if (rNum < 8) {
            plainPadding = new byte[originLength + rNum];
            System.arraycopy(plainBytes, 0, plainPadding, 0, originLength);
            for(int i = 0; i < rNum; i++){
                plainPadding[originLength + i] = (byte)rNum;
            }
        } else {
            plainPadding = plainBytes;
        }
        //将原文分为多个64位数组
        int gNum = plainPadding.length / 8;
        byte[] groupPlain = new byte[8];
        byte[] ciphert  = new byte[plainPadding.length];
        for(int i = 0; i < gNum; i++){
            System.arraycopy(plainPadding, i * 8, groupPlain, 0, 8);
            System.arraycopy(descryUnit(groupPlain, subKey, mode), 0, ciphert, i * 8, 8);
        }
        //解密
        if(mode == 0){
            byte[] plainText = new byte[p_origin_length];
            System.arraycopy(ciphert, 0, plainText, 0, p_origin_length);
            return plainText;
        }

        return ciphert;
    }

    public byte[] descryUnit(byte[] groupPlain, int[][] subKey, int mode){
        //将输入分组原文转换为二进制数存放在int数组中
        int[] plainBit = new int[64];
        StringBuilder stringBuilder = new StringBuilder();
        for(int i = 0; i < 8; i++){
            StringBuilder s = new StringBuilder(Integer.toBinaryString(groupPlain[i] & 0xff));
            while(s.length() != 8){
                s.insert(0, '0');
            }
            stringBuilder.append(s);
        }
        String plainString = stringBuilder.toString();

        for(int i = 0; i < 64; i++){
            int p = (int)plainString.charAt(i);
            if(p == 48){
                p = 0;
            }else if(p == 49){
                p = 1;
            }else{
                System.out.println("转换错误");
            }
            plainBit[i] = p;
        }

        //IP置换
        int[] plainIP = new int[64];
        for(int i = 0; i < 64; i++){
            plainIP[i] = plainBit[replaceTable.getIP()[i] - 1];
        }
        if(mode == 1) {
            //加密
            for (int i = 0; i < 16; i++) {
                separate(plainIP, subKey[i], i, mode);
            }
        }else if (mode == 0){
            //解密
            for(int i = 15 ; i > -1 ; i--){
                separate(plainIP, subKey[i], i, mode);
            }
        }

        int[] c = new int[64];
        for(int i = 0; i < replaceTable.getIP_1().length; i++){
            c[i] = plainIP[replaceTable.getIP_1()[i]-1];
        }
        byte[] cByte = new byte[8];
        for(int i = 0; i < 8; i++){
            cByte[i] = (byte)((c[8*i]<<7)+(c[8*i+1]<<6)+(c[8*i+2]<<5)+(c[8*i+3]<<4)+(c[8*i+4]<<3)+(c[8*i+5]<<2)+(c[8*i+6]<<1)+(c[8*i+7]));
        }
        return cByte;
    }

    //分组
    public void separate(int[] origin, int[] key, int times, int mode){
        int[] L0 = new int[32];
        int[] R0 = new int[32];
        int[] L1 = new int[32];
        int[] R1 = new int[32];
        int[] f = new int[32];
        System.arraycopy(origin, 0, L0, 0, 32);
        System.arraycopy(origin, 32, R0, 0 ,32);
        L1 = R0;
        f = fFunction(R0, key);
        for(int i = 0; i < 32; i++){
            R1[i] = L0[i] ^ f[i];
            if (((mode == 0) && (times == 0)) || ((mode == 1) && (times == 15))) {
                origin[i] = R1[i];
                origin[i + 32] = L1[i];
            }
            else {
                origin[i] = L1[i];
                origin[i + 32] = R1[i];
            }
        }
    }

    //f函数
    public int[] fFunction(int[] rContent, int[] key){
        int[] eReplace = new int[48];
        //置换表E扩展48位并与子密钥异或
        for(int i = 0; i < 48; i++){
            eReplace[i] = rContent[replaceTable.getE()[i] - 1] ^ key[i];
        }
        //S盒替换
        int[][] sBefore = new int[8][6];
        int[] sReplace = new int[32];
        for(int i = 0; i < 8; i++){
            System.arraycopy(eReplace, i * 6, sBefore[i], 0, 6);
            int x = (sBefore[i][0] << 1) + sBefore[i][5];
            int y = (sBefore[i][1] << 3) + (sBefore[i][2] << 2) + (sBefore[i][3] << 1) + sBefore[i][4];
            StringBuilder str = new StringBuilder(Integer.toBinaryString(replaceTable.getS_Box()[i][x][y]));
            while(str.length() < 4){
                str.insert(0, '0');
            }
            for(int j = 0; j < 4; j++){
                int p = (int)str.charAt(j);
                if(p == 48){
                    p = 0;
                }else if(p == 49){
                    p = 1;
                }else{
                    System.out.println("S盒转换错误");
                }
                sReplace[4 * i + j] = p;
            }
        }
        //P表置换
        int[] pReplace = new int[32];
        for(int i = 0; i < 32; i++){
            pReplace[i] = sReplace[replaceTable.getP()[i] - 1];
        }
        return pReplace;
    }

    //生成子密钥
    public void generateKeys(String key){
        //将密钥转化为64位二进制存储在int数组中
        StringBuilder keyBuilder = new StringBuilder(key);
        while(keyBuilder.length() < 8){
            keyBuilder.append(keyBuilder);
        }
        key = keyBuilder.toString().substring(0, 8);
        byte[] keyBytes = key.getBytes();
        int[] keyBit = new int[64];
        for(int i = 0; i < 8; i++){
            StringBuilder s = new StringBuilder(Integer.toBinaryString(keyBytes[i] & 0xff));
            if(s.length() < 8){
                for(int j = 0; j <= 8 - s.length(); j++){
                    s.insert(0, '0');
                }
            }
            for(int j = 0; j < 8; j++){
                int p = (int)s.charAt(j);
                if(p == 48){
                    p = 0;
                }else if(p == 49){
                    p = 1;
                }else{
                    System.out.println("密钥转换出错");
                }
                keyBit[i * 8 + j] = p;
            }
        }
        //PC1替换
        int[] keyPC1 = new int[56];
        for(int i = 0; i < replaceTable.getPC1().length; i++){
            keyPC1[i] = keyBit[replaceTable.getPC1()[i] - 1];
        }
        int[] c0 = new int[28];
        int[] d0 = new int[28];
        System.arraycopy(keyPC1, 0, c0, 0, 28);
        System.arraycopy(keyPC1, 28, d0, 0, 28);
        //PC2替换并左移
        for(int i = 0; i < 16; i++){
            int[] c1 = new int[28];
            int[] d1 = new int[28];
            if(replaceTable.getSLS()[i] == 1){
                System.arraycopy(c0, 1, c1, 0, 27);
                c1[27] = c0[0];
                System.arraycopy(d0, 1, d1, 0,  27);
                d1[27] = d0[0];
            }else if(replaceTable.getSLS()[i] == 2){
                System.arraycopy(c0, 2, c1, 0, 26);
                c1[26] = c0[0];
                c1[27] = c0[1];

                System.arraycopy(d0, 2, d1, 0, 26);
                d1[26] = d0[0];
                d1[27] = d0[1];
            }else{
                System.out.println("LFT Error!");
            }
            int[] tmp = new int[56];
            System.arraycopy(c1, 0, tmp, 0, 28);
            System.arraycopy(d1, 0, tmp, 28, 28);
            for (int j = 0; j < replaceTable.getPC2().length; j++){//PC2压缩置换
                subKey[i][j] = tmp[replaceTable.getPC2()[j] - 1];
            }
            c0 = c1;
            d0 = d1;
        }
    }
}
