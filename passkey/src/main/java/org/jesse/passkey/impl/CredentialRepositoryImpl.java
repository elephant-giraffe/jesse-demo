package org.jesse.passkey.impl;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import com.yubico.webauthn.data.exception.Base64UrlException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.jesse.passkey.dbaccess.Tables;
import org.jesse.passkey.dbaccess.tables.PasskeyDemo;
import org.jesse.passkey.dbaccess.tables.records.PasskeyDemoRecord;
import org.jooq.DSLContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class CredentialRepositoryImpl implements CredentialRepository {

    @Autowired
    private DSLContext dsl;

    private final PasskeyDemo PASSKEY = Tables.PASSKEY_DEMO;

    @SneakyThrows
    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        List<PasskeyDemoRecord> records =
            this.dsl.select().from(PASSKEY)
                .where(PASSKEY.USER_NAME.eq(username))
                .fetchInto(PasskeyDemoRecord.class);
        return records.stream().map(key -> {
            try {
                Set<AuthenticatorTransport> transports = Arrays.stream(key.getTransports().split(",")).map(String::toUpperCase)
                    .map(AuthenticatorTransport::valueOf).collect(Collectors.toSet());
                return PublicKeyCredentialDescriptor.builder()
                    .id(ByteArray.fromBase64Url(key.getCredId()))
                    .type(PublicKeyCredentialType.valueOf(key.getCredType()))
                    .transports(transports)
                    .build();
            } catch (Base64UrlException ex) {
                log.error("error base64url for credId, entity={}", key, ex);
                return null;
            }
        }).filter(Objects::nonNull).collect(Collectors.toSet());
    }

    @SneakyThrows
    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        String user = this.dsl
            .select(PASSKEY.USER_HANDLE)
            .from(PASSKEY)
            .where(PASSKEY.USER_NAME.eq(username))
            .limit(1)
            .fetchOne(PASSKEY.USER_HANDLE);
        return Objects.isNull(user) ? Optional.empty() : Optional.of(ByteArray.fromBase64Url(user));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        String name = this.dsl
            .select(PASSKEY.USER_NAME)
            .from(PASSKEY)
            .where(PASSKEY.USER_HANDLE.eq(userHandle.getBase64Url()))
            .limit(1)
            .fetchOne(PASSKEY.USER_NAME);
        return Optional.ofNullable(name);
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        PasskeyDemoRecord rec = this.dsl
            .selectFrom(PASSKEY)
            .where(PASSKEY.CRED_ID.eq(credentialId.getBase64Url()))
            .fetchOne();
        if (Objects.isNull(rec)) {
            return Optional.empty();
        }
        return Optional.of(toRegisteredCredential(rec));
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        PasskeyDemoRecord rec = this.dsl
            .selectFrom(PASSKEY)
            .where(PASSKEY.CRED_ID.eq(credentialId.getBase64Url()))
            .fetchOne();
        if (Objects.isNull(rec)) {
            return Collections.emptySet();
        }
        return Collections.singleton(toRegisteredCredential(rec));
    }

    private RegisteredCredential toRegisteredCredential(PasskeyDemoRecord record) {
        try {
            return RegisteredCredential.builder()
                .credentialId(ByteArray.fromBase64Url(record.getCredId()))
                .userHandle(ByteArray.fromBase64Url(record.getUserHandle()))
                .publicKeyCose(ByteArray.fromBase64Url(record.getPubKey()))
                .build();
        } catch (Base64UrlException e) {
            throw new RuntimeException(e);
        }
    }

}
