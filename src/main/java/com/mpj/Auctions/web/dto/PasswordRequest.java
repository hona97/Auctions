package com.mpj.Auctions.web.dto;

import com.mpj.Auctions.annotation.ValidPassword;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PasswordRequest {
    private String oldPassword;

    private  String token;

    @ValidPassword
    private String newPassword;

    @NotNull
    @Size(min = 1)
    private String matchingPassword;
}
