package com.mpj.Auctions.repository;

import com.mpj.Auctions.model.PasswordResetToken;
import com.mpj.Auctions.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    PasswordResetToken findByToken(String token);

    PasswordResetToken findByUser(User user);

}
