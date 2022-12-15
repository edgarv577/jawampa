package jawampa.auth.client;

import java.nio.charset.StandardCharsets;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.interfaces.Sign;
import com.goterl.lazysodium.utils.Key;

import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;
import jawampa.WampMessages.AuthenticateMessage;
import jawampa.WampMessages.ChallengeMessage;

public class CryptosignAuth implements ClientSideAuthentication {
	private static final InternalLogger logger = InternalLoggerFactory.getInstance(CryptosignAuth.class);

	private static final LazySodiumJava LAZY_SODIUM = new LazySodiumJava(new SodiumJava(),
			StandardCharsets.UTF_8);

	public static final String AUTH_METHOD = "cryptosign";

	private final ObjectNode authextra;
	private final String privkey;

	public CryptosignAuth(String privkey, String pubkey) {
		ObjectNode authextra = new ObjectMapper().createObjectNode();
		authextra.put("pubkey", pubkey);
		this.authextra = authextra;
		this.privkey = privkey;
	}

	@Override
	public String getAuthMethod() {
		return AUTH_METHOD;
	}

	@Override
	public ObjectNode getAuthExtra() {
		return authextra;
	};

	/*
	 * Only for reference:
	 * // Autobahn|JS
	 * // const privkey = autobahn.util.htob(privkeyHex);
	 * // var challenge = autobahn.util.htob(extra.challenge);
	 * // var signature = nacl.sign.detached(challenge, privkey);
	 * // return autobahn.util.btoh(signature);
	 * 
	 * // Autobahn|Java
	 * // String hexChallenge = (String) challenge.extra.get("challenge");
	 * // byte[] rawChallenge = AuthUtil.toBinary(hexChallenge);
	 * // SigningKey key = new SigningKey(privateKeyRaw);
	 * // byte[] signed = key.sign(rawChallenge);
	 * // String signatureHex = AuthUtil.toHexString(signed);
	 * // return signatureHex + hexChallenge;
	 */
	@Override
	public AuthenticateMessage handleChallenge(ChallengeMessage message,
			ObjectMapper objectMapper) {
		// get the message to sign
		final String challengeHex = (String) message.extra.get("challenge").asText();
		final byte[] challengeRaw = LazySodiumJava.toBin(challengeHex);

		// build the secret key
		final Key secretKey = Key.fromHexString(privkey);

		// cast to the proper native interface
		Sign.Native cryptoSignNative = (Sign.Native) LAZY_SODIUM;

		// try to sign message with the secret key
		byte[] signatureBytes = new byte[Sign.BYTES];
		boolean signed = cryptoSignNative.cryptoSignDetached(signatureBytes, challengeRaw, challengeRaw.length,
				secretKey.getAsBytes());
		if (logger.isDebugEnabled()) {
			logger.debug("Signing hex message: {} has returned: {}", challengeHex, signed);
		}
		String signature = LAZY_SODIUM.sodiumBin2Hex(signatureBytes);

		return new AuthenticateMessage(signature, objectMapper.createObjectNode());
	}
}
