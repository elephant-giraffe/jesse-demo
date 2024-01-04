package org.jesse.passkey.util;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.Base64UrlException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class ByteArrayUtils {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static ByteArray generateUserHandleByName(String username) throws NoSuchAlgorithmException, Base64UrlException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] rd = new byte[16];
        SECURE_RANDOM.nextBytes(rd);
        digest.update(rd);
        byte[] hashed = digest.digest(username.getBytes(StandardCharsets.UTF_8));
        return ByteArray.fromBase64Url(Base64.getUrlEncoder().withoutPadding().encodeToString(hashed));
    }

}
