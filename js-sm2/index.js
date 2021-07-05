
const { sm2 } = require('sm-crypto')
// 这里使用java 生成的key
const keypair = sm2.generateKeyPairHex();
console.log(keypair.privateKey)
console.log(keypair.publicKey)

const privateKey ='730895115e28d7cdbc5be77e0a2c39f690e04217b7218f7c36f27e293b7d1e51';
const publicKey = '0498024e7a2ad38f79223394aab9a30fd30be81c6c5efd307d520ff5f53d9d4bee2f7e62c843ae2c0ff448dc6e56297fda6154d5110ea246e4b692c2d3bda96949'
const javaEncryptData ='ba601fe569074ddfc34e4ae2925e0b62b129f0a16f8a39fa4d1bf9fe274f556695694c787cee218f3a9575fbcea5115019e8b469fe07444894b25a78e2914eb5b5a42bee510b84f64d2785dd351a200b8739a0286c04b7cc314d4c57a0998250221b22d50a4285b32f6c8132799a0a5b4117eba4e122818c'

const encryptData = sm2.doEncrypt('这是一段加密内容',publicKey,1) // 加密结果

//f8e1f01a6c9cbc3ced439ccc8137a49d831d42fea1f281ac31df1ee3ef5364ee78112a243ccc2502905efd008220a6ebac37903710bacfaa8639acbec1f4fbbe068281a7747e5fc7685232f6aee66e5c4d34b70a7afda817dc7234f18bf75539c0cbc1c49948b854cff6c07667c2fc4ab9a187b66a0e51f2
//这段内容需全大写并且加上前缀04
//04F8E1F01A6C9CBC3CED439CCC8137A49D831D42FEA1F281AC31DF1EE3EF5364EE78112A243CCC2502905EFD008220A6EBAC37903710BACFAA8639ACBEC1F4FBBE068281A7747E5FC7685232F6AEE66E5C4D34B70A7AFDA817DC7234F18BF75539C0CBC1C49948B854CFF6C07667C2FC4AB9A187B66A0E51F2
console.log("加密内容:",encryptData)
const decryptData = sm2.doDecrypt(encryptData, privateKey,1) // 解密结果
console.log("解密内容:",decryptData)


const decryptJavaData = sm2.doDecrypt(javaEncryptData,privateKey,1);

console.log("java内容解密:",decryptJavaData)
// 04
//19A4B33D291FB56FE16540B04DC32DA7EF38D1320221F2B8760BF2657CE2D90DC826FDBAC5B64BC138F25FEF2A0DAB4717FDC1580B2F03753C72374CFD2E242C628C28FE764599AE3A76BE66E27850090E23C00A123AFAB186C12070FE1EBB5986B4F19317F719452E2CCB752ACE370A026CF973D40EB407
04
//3B6C49CD34C4420F5DDC51E4E7A445065833905C6DB33BFF34E56964ABC3A9CA008B890D8933A7317E5CAE5364E7EBA324B8312082E476B01484BB4D362DDA3A93E29C89F3D4E07E98611B5FE2A1B424D3CF71BD4139E1E34265C99C8E75A78182FA90CF3F7FA08DBD44556F6D3CAB94724570A32A30FBBC