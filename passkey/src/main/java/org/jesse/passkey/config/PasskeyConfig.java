package org.jesse.passkey.config;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import org.jesse.passkey.impl.CredentialRepositoryImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import(value = {JooqConfig.class})
@ComponentScan(basePackageClasses = {CredentialRepositoryImpl.class})
public class PasskeyConfig {

    private final CredentialRepository credentialRepository;

    @Autowired
    public PasskeyConfig(CredentialRepository credentialRepository) {
        this.credentialRepository = credentialRepository;
    }

    @Bean
    public RelyingParty relyingParty() {
        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
            .id("phemex.com")  // Set this to a parent domain that covers all subdomains
            // where users' credentials should be valid
            .name("Phemex")
            .build();

        RelyingParty rp = RelyingParty.builder()
            .identity(rpIdentity)
            .credentialRepository(credentialRepository)
            .build();

        return rp;
    }

}
