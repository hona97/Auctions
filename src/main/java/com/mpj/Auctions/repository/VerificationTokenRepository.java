package com.mpj.Auctions.repository;

import com.mpj.Auctions.model.User;
import com.mpj.Auctions.model.VerificationToken;
//import com.mypp.auctionstable.web.AuthenticationResponse;
import org.springframework.data.jpa.repository.JpaRepository;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {
    VerificationToken findByToken(String token);

    VerificationToken findByUser(User user);
}
