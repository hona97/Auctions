package com.mpj.Auctions.web.dto;

import com.mpj.Auctions.annotation.ValidEmail;
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
public class EmailRequest {

    @NotNull
    @ValidEmail
    @Size(min = 1, message = "{Size.userDto.email}")
    private String email;

//    @ValidPassword
//    private String matchingNewPassword;
}
