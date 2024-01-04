package org.jesse.passkey.controller.vo;


import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RegistrationStartResponse {

    private UUID flowId;
    private PublicKeyCredentialCreationOptions options;

}
