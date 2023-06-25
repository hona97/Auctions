package com.mpj.Auctions.service;

import com.mpj.Auctions.model.*;
import com.mpj.Auctions.repository.*;
import com.mpj.Auctions.web.error.UserAlreadyExistException;
import com.mpj.Auctions.web.dto.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.env.Environment;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.maxmind.geoip2.DatabaseReader;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
public class UserService implements IUserService {
    @Autowired
    private final UserRepository repository;
    @Autowired
    private final VerificationTokenRepository tokenRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordResetTokenRepository passwordTokenRepository;

    @Autowired
    private final PasswordEncoder passwordEncoder;

    @Autowired
    private final JwtService jwtService;

//    @Autowired
//    private final UserDetailsService userDetailsService;

    @Autowired
    @Qualifier("GeoIPCountry")
    private DatabaseReader databaseReader;

    @Autowired
    private Environment env;

    @Autowired
    private SessionRegistry sessionRegistry;

    @Autowired
    private UserLocationRepository userLocationRepository;

    @Autowired
    private NewLocationTokenRepository newLocationTokenRepository;

//    @Autowired
//    private AuthenticationManager authenticationManager;

    public static final String TOKEN_INVALID = "invalidToken";
    public static final String TOKEN_EXPIRED = "expired";
    public static final String TOKEN_VALID = "valid";

    public User registerNewUserAccount(final RegisterRequest request) throws UserAlreadyExistException {
        if (repository.findByEmail(request.getEmail()) != null) {
            throw new UserAlreadyExistException("There is an account with that email address: "
                    + request.getEmail());
        }
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .address(request.getAddress())
                .avatar("/img/avatardefault.jpg")
                .roles(Arrays.asList(roleRepository.findByName("ROLE_USER")))
                .build();
        return repository.save(user);
    }

    public VerificationToken createVerificationToken(final User user) {
        var jwtToken = jwtService.generateToken(user);
        VerificationToken token = VerificationToken.builder()
                .token(jwtToken)
                .user(user)
                .build();
        return tokenRepository.save(token);
    }

    public VerificationToken getVerificationToken(final String token) {
        return tokenRepository.findByToken(token);
    }

    @Override
    public VerificationToken generateNewVerificationToken(final String existingToken) {
        VerificationToken vToken = tokenRepository.findByToken(existingToken);
        vToken.setToken(jwtService.generateToken(vToken.getUser()));
        vToken = tokenRepository.save(vToken);
        return vToken;
    }

    @Override
    public void addUserLocation(User user, String ip) {
        if(!isGeoIpLibEnabled()) {
            return;
        }

        try {
            final InetAddress ipAddress = InetAddress.getByName(ip);
            final String country = databaseReader.country(ipAddress)
                    .getCountry()
                    .getName();
//            UserLocation loc = new UserLocation(country, user);
//            loc.setEnabled(true);
//            userLocationRepository.save(loc);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public User findUserByEmail(final String userEmail) {
        return repository.findByEmail(userEmail);
    }

    @Override
    public PasswordResetToken createPasswordResetTokenForUser(final User user) {
        var jwtToken = jwtService.generateToken(user);
        PasswordResetToken token = PasswordResetToken.builder()
                .token(jwtToken)
                .user(user)
                .build();
        return passwordTokenRepository.save(token);
    }

    @Override
    public Optional<User> getUserByPasswordResetToken(final String token) {
        return Optional.ofNullable(passwordTokenRepository.findByToken(token).getUser());
    }

    @Override
    public void changeUserPassword(final User user, final String password) {
        user.setPassword(passwordEncoder.encode(password));
        repository.save(user);
    }

    private boolean isGeoIpLibEnabled() {
        return Boolean.parseBoolean(env.getProperty("geo.ip.lib.enabled"));
    }


    public String validateVerificationToken(String token) {
        final VerificationToken verificationToken = tokenRepository.findByToken(token);
        if (verificationToken == null) {
            return TOKEN_INVALID;
        }
        final User user = verificationToken.getUser();
        if (!jwtService.isTokenValid(verificationToken.getToken(), user)) {
            tokenRepository.delete(verificationToken);
            return TOKEN_EXPIRED;
        }

        user.setEnabled(true);
        // tokenRepository.delete(verificationToken);
        repository.save(user);
        return TOKEN_VALID;
    }

    @Override
    public User getUser(final String verificationToken) {
        final VerificationToken token = tokenRepository.findByToken(verificationToken);
        if (token != null) {
            return token.getUser();
        }
        return null;
    }

    @Override
    public void saveRegisteredUser(final User user) {
        repository.save(user);
    }

    @Override
    public boolean checkIfValidOldPassword(final User user, final String oldPassword) {
        return passwordEncoder.matches(oldPassword, user.getPassword());
    }

    @Override
    public List<String> getUsersFromSessionRegistry() {
        return sessionRegistry.getAllPrincipals()
                .stream()
                .filter((u) -> !sessionRegistry.getAllSessions(u, false)
                        .isEmpty())
                .map(o -> {
                    if (o instanceof User) {
                        return ((User) o).getEmail();
                    } else {
                        return o.toString()
                                ;
                    }
                }).collect(Collectors.toList());
    }

    @Override
    public NewLocationToken isNewLoginLocation(String username, String ip) {

        if(!isGeoIpLibEnabled()) {
            return null;
        }

        try {
            final InetAddress ipAddress = InetAddress.getByName(ip);
            final String country = databaseReader.country(ipAddress)
                    .getCountry()
                    .getName();
            System.out.println(country + "====****");
            final User user = repository.findByEmail(username);
            final UserLocation loc = userLocationRepository.findByCountryAndUser(country, user);
            if ((loc == null) || !loc.isEnabled()) {
                return createNewLocationToken(country, user);
            }
        } catch (final Exception e) {
            return null;
        }
        return null;
    }

    private NewLocationToken createNewLocationToken(String country, User user) {
        UserLocation loc = new UserLocation(country, user);
        loc = userLocationRepository.save(loc);

        final NewLocationToken token = new NewLocationToken(UUID.randomUUID()
                .toString(), loc);
        return newLocationTokenRepository.save(token);
    }

//    public User authenticate(final LoginRequest request) throws UserNotFoundException {
//        authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(
//                        request.getEmail(),
//                        request.getPassword()
//                )
//        );
//        var user = repository.findByEmail(request.getEmail());
//        if (user != null) {
//            throw new UserNotFoundException("There is have no account with that email address: "
//                    + request.getEmail());
//        }
//        return user;
//    }


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
}
