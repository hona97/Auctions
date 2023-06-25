package com.mpj.Auctions.repository;

import com.mpj.Auctions.model.NewLocationToken;
import com.mpj.Auctions.model.UserLocation;
import org.springframework.data.jpa.repository.JpaRepository;

public interface NewLocationTokenRepository extends JpaRepository<NewLocationToken, Long> {

    NewLocationToken findByToken(String token);

    NewLocationToken findByUserLocation(UserLocation userLocation);

}
