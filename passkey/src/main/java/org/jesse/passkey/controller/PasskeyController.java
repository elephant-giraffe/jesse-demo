package org.jesse.passkey.controller;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.UUID;
import javax.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.jesse.passkey.controller.vo.AuthenticationFinishRequest;
import org.jesse.passkey.controller.vo.AuthenticationStartRequest;
import org.jesse.passkey.controller.vo.AuthenticationStartResponse;
import org.jesse.passkey.controller.vo.RegistrationFinishRequest;
import org.jesse.passkey.controller.vo.RegistrationFinishResponse;
import org.jesse.passkey.controller.vo.RegistrationStartRequest;
import org.jesse.passkey.controller.vo.RegistrationStartResponse;
import org.jesse.passkey.dbaccess.Tables;
import org.jesse.passkey.util.ByteArrayUtils;
import org.jooq.DSLContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * passkey demo controller
 * <p>
 * @author jesse.xu
 * @date 2022-05-06
 **/
@Slf4j
@Controller
@RequestMapping("/webauthn")
public class PasskeyController {

    private final SecureRandom random = new SecureRandom();

    @Autowired
    private DSLContext dsl;
    @Autowired
    private RelyingParty relyingParty;
    @Autowired
    private CredentialRepository credentialRepository;

    @PostMapping("/register/start")
    @ResponseBody
    public RegistrationStartResponse registerStart(@RequestBody RegistrationStartRequest startRequest) throws Base64UrlException, NoSuchAlgorithmException {
        log.info("register start, request={}", startRequest);
        // 查询用户信息
        String email = startRequest.getEmail();
        // 对应的userHandle
        ByteArray handle = ByteArrayUtils.generateUserHandleByName(email);
        log.info("user={}, handle={}", email, handle);
        // UserIdentity对象，WebAuthn的User信息
        UserIdentity userIdentity =
            UserIdentity.builder()
                .name(email)
                .displayName(email)
                .id(handle)
                .build();
        // Passkey的验证偏好
        AuthenticatorSelectionCriteria authenticatorSelectionCriteria =
            AuthenticatorSelectionCriteria.builder()
                .userVerification(UserVerificationRequirement.PREFERRED)
                .build();
        // Passkey注册参数
        StartRegistrationOptions startRegistrationOptions =
            StartRegistrationOptions.builder()
                .user(userIdentity)
                .timeout(60_000)
                .authenticatorSelection(authenticatorSelectionCriteria)
                .build();
        // 返回给前端用于WebAuthn认证的参数
        PublicKeyCredentialCreationOptions options =
            this.relyingParty.startRegistration(startRegistrationOptions);
        // todo 将CreationOptions保存在redis，验证时需要再次使用
        UUID uuid = UUID.randomUUID();
        // saveToRedis(uuid.toString(), options);
        // 返回结果
        return RegistrationStartResponse.builder().flowId(uuid).options(options).build();
    }

    @PostMapping("/register/finish")
    @ResponseBody
    public RegistrationFinishResponse registerFinish(@RequestBody RegistrationFinishRequest finishRequest) throws RegistrationFailedException {
        log.info("register finish, request={}", finishRequest);
        // 从redis中取回start时的CreationOptions
        // fetchFromRedis(request.getFlowId());
        PublicKeyCredentialCreationOptions startOptions = null;
        if (Objects.isNull(startOptions)) {
            throw new RuntimeException("Cloud Not find the original request");
        }
        // 验证前端的授权参数
        FinishRegistrationOptions options =
            FinishRegistrationOptions.builder()
                .request(startOptions)
                .response(finishRequest.getCredential())
                .build();
        RegistrationResult registrationResult = this.relyingParty.finishRegistration(options);
        // 验证完成，记录用户数据
        this.dsl.transaction(tr -> {
            tr.dsl().insertInto(Tables.PASSKEY_DEMO)
                .set(Tables.PASSKEY_DEMO.CRED_ID, registrationResult.getKeyId().getId().getBase64Url())
                .set(Tables.PASSKEY_DEMO.USER_HANDLE, startOptions.getUser().getId().getBase64Url())
                .set(Tables.PASSKEY_DEMO.USER_NAME, startOptions.getUser().getName())
                .set(Tables.PASSKEY_DEMO.PUB_KEY, registrationResult.getPublicKeyCose().getBase64Url())
                .set(Tables.PASSKEY_DEMO.STATUS, "active") // active, deleted
                // .onDuplicateKeyIgnore()
                .onDuplicateKeyUpdate()
                .set(Tables.PASSKEY_DEMO.CRED_ID, registrationResult.getKeyId().getId().getBase64Url())
                .set(Tables.PASSKEY_DEMO.USER_HANDLE, startOptions.getUser().getId().getBase64Url())
                .set(Tables.PASSKEY_DEMO.USER_NAME, startOptions.getUser().getName())
                .set(Tables.PASSKEY_DEMO.PUB_KEY, registrationResult.getPublicKeyCose().getBase64Url())
                .set(Tables.PASSKEY_DEMO.STATUS, "active") // active, deleted
                .execute();
        });
        // 返回结果
        RegistrationFinishResponse registrationFinishResponse = new RegistrationFinishResponse();
        registrationFinishResponse.setFlowId(finishRequest.getFlowId());
        registrationFinishResponse.setRegistrationComplete(true);
        return registrationFinishResponse;
    }

    @PostMapping("/authenticate/start")
    @ResponseBody
    public AuthenticationStartResponse authenticateStart(@RequestBody AuthenticationStartRequest startRequest) throws Base64UrlException {
        log.info("authenticate start, request={}", startRequest);
        // 查询用户信息
        String email = startRequest.getEmail();
        String userBase64Url = this.dsl.select(Tables.PASSKEY_DEMO.USER_HANDLE)
            .from(Tables.PASSKEY_DEMO)
            .where(Tables.PASSKEY_DEMO.USER_NAME.eq(email))
            .limit(1)
            .fetchOne(Tables.PASSKEY_DEMO.USER_HANDLE);
        // Passkey认证的请求参数
        StartAssertionOptions options = StartAssertionOptions.builder()
            .timeout(60_000)
            .username(startRequest.getEmail())
            .userHandle(ByteArray.fromBase64Url(userBase64Url))
            .build();
        AssertionRequest assertionRequest = this.relyingParty.startAssertion(options);
        // todo 将CreationOptions保存在redis，验证时需要再次使用
        UUID uuid = UUID.randomUUID();
        // saveToRedis(uuid.toString(), assertionRequest);
        // 返回前端
        AuthenticationStartResponse startResponse = AuthenticationStartResponse.builder()
            .flowId(uuid)
            .assertionRequest(assertionRequest)
            .build();
        return startResponse;
    }

    @PostMapping("/authenticate/finish")
    public AssertionResult authenticateFinish(@RequestBody AuthenticationFinishRequest finishRequest) throws AssertionFailedException {
        log.info("authenticate finish, request={}", finishRequest);
        // 从redis中取回start时的AssertionRequest
        // fetchFromRedis(finishRequest.getFlowId());
        AssertionRequest assertionRequest = null;
        if (Objects.isNull(assertionRequest)) {
            throw new RuntimeException("Cloud Not find the original request");
        }
        // 验证前端的PublicKeyCredential
        FinishAssertionOptions options =
            FinishAssertionOptions.builder()
                .request(assertionRequest)
                .response(finishRequest.getCredential())
                .build();
        AssertionResult assertionResult = this.relyingParty.finishAssertion(options);
        if (!assertionResult.isSuccess()) {
            throw new RuntimeException("assert public key credential failed");
        }
        return assertionResult;
    }

    @PostConstruct
    public void afterPropertiesSet() {

    }

}
