import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.security.KeyPair;

/**
 * @author lxc
 * @Date 2021/7/5
 */
public class TestClass {
    public static void main(String[] args) {
        String text ="这是一段加密内容";
        // 随机生成秘钥
         KeyPair pair = SecureUtil.generateKeyPair("SM2");
         byte[] privateKey = pair.getPrivate().getEncoded();
         byte[] publicKey = pair.getPublic().getEncoded();
         /*私钥
          完整:308193020100301306072a8648ce3d020106082a811ccf5501822d047930770201010420730895115e28d7cdbc5be77e0a2c39f690e04217b7218f7c36f27e293b7d1e51a00a06082a811ccf5501822da1440342000498024e7a2ad38f79223394aab9a30fd30be81c6c5efd307d520ff5f53d9d4bee2f7e62c843ae2c0ff448dc6e56297fda6154d5110ea246e4b692c2d3bda96949
          拆解:
          308193020100301306072a8648ce3d0201
          06082a811ccf5501822d
          047930770201010420
          730895115e28d7cdbc5be77e0a2c39f690e04217b7218f7c36f27e293b7d1e51  //即为js私钥
          a00a
          06082a811ccf5501822d
          a144
          034200
          0498024e7a2ad38f79223394aab9a30fd30be81c6c5efd307d520ff5f53d9d4bee2f7e62c843ae2c0ff448dc6e56297fda6154d5110ea246e4b692c2d3bda96949

         */
         System.out.printf("privateKey:%s \n",HexUtil.encodeHexStr(privateKey));
          /* 公钥
           完整:3059301306072a8648ce3d020106082a811ccf5501822d0342000498024e7a2ad38f79223394aab9a30fd30be81c6c5efd307d520ff5f53d9d4bee2f7e62c843ae2c0ff448dc6e56297fda6154d5110ea246e4b692c2d3bda96949
           拆解:
           3059301306072a8648ce3d0201
           06082a811ccf5501822d
           034200
    js公钥: 0498024e7a2ad38f79223394aab9a30fd30be81c6c5efd307d520ff5f53d9d4bee2f7e62c843ae2c0ff448dc6e56297fda6154d5110ea246e4b692c2d3bda96949
         */
        System.out.printf("publicKey:%s \n",HexUtil.encodeHexStr(publicKey));


        SM2 sm2 = SmUtil.sm2(privateKey,publicKey);

         // 公钥加密
         String encryptStr = sm2.encryptBcd(text, KeyType.PublicKey);
         // 04BA601FE569074DDFC34E4AE2925E0B62B129F0A16F8A39FA4D1BF9FE274F556695694C787CEE218F3A9575FBCEA5115019E8B469FE07444894B25A78E2914EB5B5A42BEE510B84F64D2785DD351A200B8739A0286C04B7CC314D4C57A0998250221B22D50A4285B32F6C8132799A0A5B4117EBA4E122818C
         // 去掉前置04并且全小写 js可解密内容：
         // ba601fe569074ddfc34e4ae2925e0b62b129f0a16f8a39fa4d1bf9fe274f556695694c787cee218f3a9575fbcea5115019e8b469fe07444894b25a78e2914eb5b5a42bee510b84f64d2785dd351a200b8739a0286c04b7cc314d4c57a0998250221b22d50a4285b32f6c8132799a0a5b4117eba4e122818c
         System.out.printf("encryptStr:%s \n",encryptStr);
         // 私钥解密
         String decryptStr = StrUtil.utf8Str(sm2.decryptFromBcd(encryptStr, KeyType.PrivateKey));
         System.out.printf("decryptStr:%s \n",decryptStr);

         // js加密内容 java解密 已做过处理
        SM2 sm3 = SmUtil.sm2(ByteUtils.fromHexString("308193020100301306072a8648ce3d020106082a811ccf5501822d047930770201010420730895115e28d7cdbc5be77e0a2c39f690e04217b7218f7c36f27e293b7d1e51a00a06082a811ccf5501822da1440342000498024e7a2ad38f79223394aab9a30fd30be81c6c5efd307d520ff5f53d9d4bee2f7e62c843ae2c0ff448dc6e56297fda6154d5110ea246e4b692c2d3bda96949"),ByteUtils.fromHexString("3059301306072a8648ce3d020106082a811ccf5501822d0342000498024e7a2ad38f79223394aab9a30fd30be81c6c5efd307d520ff5f53d9d4bee2f7e62c843ae2c0ff448dc6e56297fda6154d5110ea246e4b692c2d3bda96949"));
        String jsEncryptStr ="04F8E1F01A6C9CBC3CED439CCC8137A49D831D42FEA1F281AC31DF1EE3EF5364EE78112A243CCC2502905EFD008220A6EBAC37903710BACFAA8639ACBEC1F4FBBE068281A7747E5FC7685232F6AEE66E5C4D34B70A7AFDA817DC7234F18BF75539C0CBC1C49948B854CFF6C07667C2FC4AB9A187B66A0E51F2";
        String jsDecryptStr = StrUtil.utf8Str(sm3.decryptFromBcd(jsEncryptStr, KeyType.PrivateKey));

        System.out.printf("jsDecryptStr:%s \n",jsDecryptStr);
    }
}
