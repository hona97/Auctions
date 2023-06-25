package com.mpj.Auctions.repository;

import com.mpj.Auctions.model.User;
import com.mpj.Auctions.model.UserLocation;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserLocationRepository extends JpaRepository<UserLocation, Long> {
    UserLocation findByCountryAndUser(String country, User user);

}
