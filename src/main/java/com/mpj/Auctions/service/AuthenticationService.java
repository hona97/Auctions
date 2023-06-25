package com.mpj.Auctions.service;//package com.mypp.auctionstable.service;
//
//import com.mypp.auctionstable.exception.UserAlreadyExistException;
//import com.mypp.auctionstable.model.Role;
//import com.mypp.auctionstable.model.User;
//import com.mypp.auctionstable.repository.UserRepository;
//import com.mypp.auctionstable.repository.VerificationTokenRepository;
//import com.mypp.auctionstable.web.AuthenticationRequest;
//import com.mypp.auctionstable.web.AuthenticationResponse;
//import com.mypp.auctionstable.web.RegisterRequest;
//import lombok.RequiredArgsConstructor;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Service;
//
//import java.util.Calendar;
//import java.util.Optional;
//
//@Service
//@RequiredArgsConstructor
//public class AuthenticationService {
//    @Autowired
//    private final UserRepository repository;
//    @Autowired
//    private final VerificationTokenRepository tokenRepository;
//    private final PasswordEncoder passwordEncoder;
//    private final JwtService jwtService;
//    private final AuthenticationManager authenticationManager;
//    private final UserDetailsService userDetailsService;
//
//    public static final String TOKEN_INVALID = "invalidToken";
//    public static final String TOKEN_EXPIRED = "expired";
//    public static final String TOKEN_VALID = "valid";
//    public User register(RegisterRequest request) throws UserAlreadyExistException {
//        if (repository.findByEmail(request.getEmail()).isEmpty()) {
//            throw new UserAlreadyExistException("There is an account with that email address: "
//                    + request.getEmail());
//        }
//        var user = User.builder()
//                .firstname(request.getFirstname())
//                .lastname(request.getLastname())
//                .email(request.getEmail())
//                .password(passwordEncoder.encode(request.getPassword()))
//                .address(request.getAddress())
//                .age(request.getAge())
//                .avatar("/img/avatardefault.jpg")
//                .role(Role.USER)
//                .build();
//        return repository.save(user);
////        var jwtToken = jwtService.generateToken(user);
////        return AuthenticationResponse.builder()
////                .token(jwtToken)
////                .build();
//    }
//
//    public AuthenticationResponse createVerificationToken(User user) {
//        var jwtToken = jwtService.generateToken(user);
//        AuthenticationResponse token = AuthenticationResponse.builder()
//                .token(jwtToken)
//                .build();
//        return tokenRepository.save(token);
//    }
//
//    public AuthenticationResponse getVerificationToken(String token) {
//        return tokenRepository.findByToken(token);
//    }
//
//
//    public String validateVerificationToken(String token) {
//        final AuthenticationResponse verificationToken = tokenRepository.findByToken(token);
//        if (verificationToken == null) {
//            return TOKEN_INVALID;
//        }
//        final String userEmail = jwtService.extractUserName(token);
//        final User user = (User) this.userDetailsService.loadUserByUsername(userEmail);
//        final Calendar cal = Calendar.getInstance();
//        if (!jwtService.isTokenValid(verificationToken.getToken(), user)) {
//            tokenRepository.delete(verificationToken);
//            return TOKEN_EXPIRED;
//        }
//
//        user.setEnabled(true);
//        // tokenRepository.delete(verificationToken);
//        repository.save(user);
//        return TOKEN_VALID;
//    }
//
//
//    public AuthenticationResponse authenticate(AuthenticationRequest request) {
//        authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(
//                        request.getEmail(),
//                        request.getPassword()
//                )
//        );
//        var user = repository.findByEmail(request.getEmail())
//                .orElseThrow();
//        var jwtToken = jwtService.generateToken(user);
//        return AuthenticationResponse.builder()
//                .token(jwtToken)
//                .build();
//    }
//}
