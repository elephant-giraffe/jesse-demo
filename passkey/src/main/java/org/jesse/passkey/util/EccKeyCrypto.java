package org.jesse.passkey.util;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import javax.crypto.Cipher;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.util.StopWatch;

/**
 * ECC KEY Crypto<p>
 * <p>
 * @author jesse.xu
 **/
@Slf4j
public class EccKeyCrypto {

	// EC
	private static final String EC_ALGORITHM = "EC";
	// BC
	private static final String EC_PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
	// Curve Parameter
	private static final String SECP_256_R1 = "secp256r1";
	private static final String SECP_384_R1 = "secp384r1";
	// ECDSA signature algorithm
	public static final String ECDSA_SHA256 = "SHA256withECDSA";
	private static final String ECDSA_SHA384 = "SHA384withECDSA";
	// ECIES encryption algorithm
	private static final String ECIES_ALGORITHM = "ECIES";

	// thread-safe
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();
	// thread-safe
	private static final Decoder BASE64_DECODER = Base64.getUrlDecoder();
	// thread-safe
	private static final Encoder BASE64_ENCODER = Base64.getUrlEncoder();
	// thread-safe
	private static final Decoder BASE64_KEY_DECODER = Base64.getDecoder();
	// thread-safe
	private static final Encoder BASE64_KEY_ENCODER = Base64.getEncoder();

	static {
		if (Security.getProvider(EC_PROVIDER) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	/**
	 * generate 256-bits ECC KeyPair(privateKey, publicKey)
	 * @return 密钥对象
	 */
	public static Pair<String, String> generateKeyPair(String algo)
		throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(EC_ALGORITHM, EC_PROVIDER);
		ECGenParameterSpec spec = new ECGenParameterSpec(algo);
		kpg.initialize(spec, SECURE_RANDOM);
		KeyPair keyPair = kpg.generateKeyPair();
		String privateKey = BASE64_KEY_ENCODER.encodeToString(keyPair.getPrivate().getEncoded());
		String publicKey = BASE64_KEY_ENCODER.encodeToString(keyPair.getPublic().getEncoded());
		return Pair.of(privateKey, publicKey);
	}

	/**
	 * X509EncodedKeySpec: 表示公钥的ASN.1编码
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	private static PublicKey getPublicKey(String publicKey) throws Exception {
		byte[] decode = BASE64_KEY_DECODER.decode(publicKey.getBytes(StandardCharsets.UTF_8));
		return KeyFactory.getInstance(EC_ALGORITHM).generatePublic(new X509EncodedKeySpec(decode));
	}

	/**
	 * PKCS8EncodedKeySpec: 表示私有密钥的ASN.1编码
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	private static PrivateKey getPrivateKey(String privateKey) throws Exception {
		byte[] decode = BASE64_KEY_DECODER.decode(privateKey.getBytes(StandardCharsets.UTF_8));
		return KeyFactory.getInstance(EC_ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(decode));
	}

	/**
	 * sign msg with private key
	 * @return signature
	 */
	public static String sign(String algorithm, String msg, String privateKey) throws Exception {
		PrivateKey key = getPrivateKey(privateKey);
		Signature algo = Signature.getInstance(algorithm);
		algo.initSign(key);
		algo.update(msg.getBytes(StandardCharsets.UTF_8));
		return BASE64_ENCODER.encodeToString(algo.sign());
	}

	/**
	 * verify signature with public key
	 * @param msg
	 * @param publicKey
	 * @param signature
	 * @return
	 */
	public static boolean verify(String algorithm, String msg, String publicKey, String signature) throws Exception {
		PublicKey key = getPublicKey(publicKey);
		Signature algo = Signature.getInstance(algorithm);
		algo.initVerify(key);
		algo.update(msg.getBytes());
		return algo.verify(BASE64_DECODER.decode(signature));
	}

	/**
	 * encrypt with public key
	 * @param publicKey
	 * @param plain
	 * @return
	 */
	public static String encrypt(String plain, String publicKey) throws Exception {
		try {
			Cipher cip = Cipher.getInstance(ECIES_ALGORITHM, EC_PROVIDER);
			cip.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
			byte[] res = cip.doFinal(plain.getBytes(StandardCharsets.UTF_8));
			return BASE64_ENCODER.encodeToString(res);
		} catch (Exception ex) {
			log.error("ECC encrypt failure, plain={}", plain, ex);
			throw ex;
		}
	}

	/**
	 * encrypt with private key
	 * @param privateKey
	 * @param cipher
	 * @return
	 */
	public static String decrypt(String cipher, String privateKey) throws Exception {
		try {
			byte[] cipherBytes = BASE64_DECODER.decode(cipher.getBytes(StandardCharsets.UTF_8));
			Cipher cip = Cipher.getInstance(ECIES_ALGORITHM, EC_PROVIDER);
			cip.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));
			return new String(cip.doFinal(cipherBytes));
		} catch (Exception ex) {
			log.error("ECC decrypt failure, cipher={}", cipher, ex);
			throw ex;
		}
	}

}
