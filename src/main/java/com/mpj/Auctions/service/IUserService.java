package com.mpj.Auctions.service;

import com.mpj.Auctions.model.NewLocationToken;
import com.mpj.Auctions.model.PasswordResetToken;
import com.mpj.Auctions.model.User;
import com.mpj.Auctions.model.VerificationToken;
//import com.mypp.auctionstable.web.AuthenticationResponse;
import com.mpj.Auctions.web.dto.RegisterRequest;

import java.util.List;
import java.util.Optional;

public interface IUserService {
    User registerNewUserAccount(RegisterRequest request);

    VerificationToken createVerificationToken(User user);

    String validateVerificationToken(String token);
    User getUser(String verificationToken);

    void saveRegisteredUser(User user);

    VerificationToken getVerificationToken(String verificationToken);

    VerificationToken generateNewVerificationToken(String existingToken);

    void addUserLocation(User registered, String clientIP);

    User findUserByEmail(String userEmail);

    PasswordResetToken createPasswordResetTokenForUser(User user);

    Optional<User> getUserByPasswordResetToken(String token);

    void changeUserPassword(User user, String newPassword);

    boolean checkIfValidOldPassword(User user, String oldPassword);

    List<String> getUsersFromSessionRegistry();

    NewLocationToken isNewLoginLocation(String username, String ip);
}
