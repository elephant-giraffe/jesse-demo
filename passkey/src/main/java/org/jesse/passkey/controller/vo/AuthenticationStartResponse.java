package org.jesse.passkey.controller.vo;

import com.yubico.webauthn.AssertionRequest;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthenticationStartResponse {

    private UUID flowId;
    private AssertionRequest assertionRequest;

}
