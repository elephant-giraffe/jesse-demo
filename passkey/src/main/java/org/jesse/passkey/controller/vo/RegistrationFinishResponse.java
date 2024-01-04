package org.jesse.passkey.controller.vo;

import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RegistrationFinishResponse {

    private UUID flowId;
    private boolean registrationComplete;

}
