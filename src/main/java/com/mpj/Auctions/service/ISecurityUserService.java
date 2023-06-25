package com.mpj.Auctions.service;

public interface ISecurityUserService {
    String validatePasswordResetToken(String token);
}
