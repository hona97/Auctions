package com.mpj.Auctions.web.dto;

import com.mpj.Auctions.annotation.PasswordMatches;
import com.mpj.Auctions.annotation.ValidEmail;
import com.mpj.Auctions.annotation.ValidPassword;
import jakarta.validation.constraints.NotEmpty;
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
@PasswordMatches
public class RegisterRequest {
    @NotNull
    @Size(min = 1, message = "{Size.userDto.firstName}")
    private String firstName;

    @NotNull
    @Size(min = 1, message = "{Size.userDto.lastName}")
    private String lastName;

    @NotNull
    @ValidEmail
    @Size(min = 1, message = "{Size.userDto.email}")
    private String email;

    @ValidPassword
    private String password;

    @NotNull
    @Size(min = 1)
    private String matchingPassword;

    @NotNull
    @NotEmpty
    private String address;

//    @NotNull
//    @NotEmpty
    private String avatar;

    private Integer role;

    @Override
    public String toString() {
        final StringBuilder builder = new StringBuilder();
        builder.append("UserDto [firstName=")
                .append(firstName)
                .append(", lastName=")
                .append(lastName)
                .append(", email=")
                .append(email)
                .append(", role=")
                .append(role).append("]");
        return builder.toString();
    }

}
