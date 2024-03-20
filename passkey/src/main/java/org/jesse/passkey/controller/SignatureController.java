package org.jesse.passkey.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jesse.passkey.util.EccKeyCrypto;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/signature")
@RestController
@Slf4j
public class SignatureController {

	public final static String PUBLIC_KEY =
		"MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFlH/XCc9KsThGL5UIzi40YMQckX2WQS6"
			+ "Ge8yRb0Jh6LKl0an/b/KuHdwMLY7wkkmkI9FA1DItFPL//5DV9gTUybb/zA4JlVR"
			+ "V0/XRp4BaEL2LagiHWbY3Jx1t2Siqcm1";
	public final static String PRIVATE_KEY =
		"MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDA4/HJkQQA8WYXWxl3D"
			+ "HbtnG7M7BoHGIVtLjEKL6wPt4L5Ld1ZOcP2rQWK2RnO3Wh2hZANiAAQWUf9cJz0q"
			+ "xOEYvlQjOLjRgxByRfZZBLoZ7zJFvQmHosqXRqf9v8q4d3AwtjvCSSaQj0UDUMi0"
			+ "U8v//kNX2BNTJtv/MDgmVVFXT9dGngFoQvYtqCIdZtjcnHW3ZKKpybU=";

	private final static String GET_SIGNATURE =
		"MGUCMAF7Jb5_iihyH65nIN4w9f_n8JXAj6NEyWQFVXFr8o8xRCk39BGhkzOl8fA1g920zAI"
			+ "xAIXN5R9tOY7bH7qVGgGSku0BV05LWdz42G-0SLCdXKgoEBaWGsegiT7rzA2tX8W4_w==";
	private final static String POST_SIGNATURE =
		"MGUCMF9m2G1dtXyQO-P7ERwGcI0vPhgQsecdW5XL44pz7RJiiBkuFPEeo04fH9PYYXKG4QIx"
			+ "AIHQjTs0gXAb7fYPdF_9-LeTUrXoIBjvUmEwYOQ1y7Sj_WrwL29sqIhUXPkejrf8YQ==";

	private final static String GET_MSG = "GET&/signature/get&1710922272&side=buy&token=USDT";
	private final static String POST_MSG = "POST&/signature/post&1710922272&{\"side\":\"buy\",\"token\":\"USD\"}";


	private final static String CURVE_PARAMETER = "secp384r1";

	private static final String SIGNATURE_ALGO = "SHA384withECDSA";

	@GetMapping("/get")
	@ResponseBody
	public String verifyGet(HttpServletRequest request,
		@RequestHeader("Sbg-Request-Expiry") Long ts,
		@RequestHeader("Sbg-Request-Signature") String signature,
		@RequestParam("token") String token,
		@RequestParam("side") String side) throws Exception {
		String method = request.getMethod().toUpperCase();
		String path = request.getRequestURI();
		String params = request.getQueryString();
		String msg = Stream.of(method, path, String.valueOf(ts), params)
			.filter(StringUtils::isNotBlank)
			.collect(Collectors.joining("&"));
		log.info("msg for sign = [{}]", msg);
		boolean verify = EccKeyCrypto.verify(SIGNATURE_ALGO, msg, PUBLIC_KEY, signature);
		log.info("verify result = [{}]", verify);
		return String.valueOf(verify);
	}

	@PostMapping("/post")
	@ResponseBody
	public String verifyPost(HttpServletRequest request,
		@RequestHeader("Sbg-Request-Expiry") Long ts,
		@RequestHeader("Sbg-Request-Signature") String signature,
		@RequestBody TreeMap<String, String> treeMap) throws Exception {
		String method = request.getMethod().toUpperCase();
		String path = request.getRequestURI();
		String jsonString = new ObjectMapper().writeValueAsString(treeMap);
		String msg = Stream.of(method, path, String.valueOf(ts), jsonString)
			.filter(StringUtils::isNotBlank)
			.collect(Collectors.joining("&"));
		log.info("msg for sign = [{}]", msg);
		boolean verify = EccKeyCrypto.verify(SIGNATURE_ALGO, msg, PUBLIC_KEY, signature);
		log.info("verify result = [{}]", verify);
		return String.valueOf(verify);
	}

}
