package com.mpj.Auctions.web.controller;

import com.mpj.Auctions.email.EmailSender;
import com.mpj.Auctions.event.OnRegistrationCompleteEvent;
import com.mpj.Auctions.web.error.InvalidOldPasswordException;
import com.mpj.Auctions.model.*;
import com.mpj.Auctions.repository.UserRepository;
import com.mpj.Auctions.service.ISecurityUserService;
import com.mpj.Auctions.service.IUserService;
import com.mpj.Auctions.service.JwtService;
import com.mpj.Auctions.web.util.GenericResponse;
import com.mpj.Auctions.web.dto.PasswordRequest;
import com.mpj.Auctions.web.dto.RegisterRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.MessageSource;
import org.springframework.core.env.Environment;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;


import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.Collectors;

@Controller
@RequiredArgsConstructor
public class RegistrationController {

    private final Logger LOGGER = LoggerFactory.getLogger(getClass());
    @Autowired
    private final IUserService userService;

    @Autowired
    private ISecurityUserService securityUserService;

    @Autowired
    private final UserRepository repository;

    @Autowired
    private final JwtService jwtService;

//    @Autowired
//    private final UserDetailsService userDetailsService;

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private ApplicationEventPublisher eventPublisher;

    @Autowired
    private MessageSource messages;

    @Autowired
    private Environment env;

    @Autowired
    private final EmailSender emailSender;

//    @PostMapping("/register")
//    public ModelAndView register(
//            @ModelAttribute("user") @Valid RegisterRequest registerRequest, HttpServletRequest request
//    ) {
//        LOGGER.debug("Registering user account with information: {}", registerRequest);
//        try {
//            final User user = userService.registerNewUserAccount(registerRequest);
//            final String appUrl = getAppUrl(request);
//            eventPublisher.publishEvent(new OnRegistrationCompleteEvent(user,
//                    request.getLocale(), appUrl));
//        } catch (UserAlreadyExistException uaeEx) {
//            ModelAndView mav = new ModelAndView("registration", "user", registerRequest);
//            String errMessage = messages.getMessage("message.regError", null, request.getLocale());
//            mav.addObject("message", errMessage);
//            return mav;
//        } catch (RuntimeException ex) {
//            LOGGER.warn("Unable to register user", ex);
//            return new ModelAndView("emailError", "user", registerRequest);
//        }
//        return new ModelAndView("successRegister", "user", registerRequest);
//    }

    @GetMapping("/registration")
    public ModelAndView registration(final HttpServletRequest request,
                                     final ModelMap model,
                                     @RequestParam("messageKey") final Optional<String> messageKey,
                                     @RequestParam("error") final Optional<String> error) {
        Locale locale = request.getLocale();
        model.addAttribute("lang", locale.getLanguage());
        messageKey.ifPresent( key -> {
                    String message = messages.getMessage(key, null, locale);
                    model.addAttribute("message", message);
                }
        );

        error.ifPresent( e ->  model.addAttribute("error", e));

        return new ModelAndView("registration", model);
    }

    // Registration
    @PostMapping("/user/registration")
    public GenericResponse registerUserAccount(
            @Valid final RegisterRequest registerRequest, final HttpServletRequest request) {
        LOGGER.debug("Registering user account with information: {}", registerRequest);

        final User registered = userService.registerNewUserAccount(registerRequest);
        userService.addUserLocation(registered, getClientIP(request));
        eventPublisher.publishEvent(new OnRegistrationCompleteEvent(registered, request.getLocale(), getAppUrl(request)));
        return new GenericResponse("success");
    }

    @GetMapping("/registrationConfirm")
    public ModelAndView confirmRegistration
            (final HttpServletRequest request,final ModelMap model,final @RequestParam("token") String token)
            throws UnsupportedEncodingException {
        Locale locale = request.getLocale();
        model.addAttribute("lang", locale.getLanguage());

        final String verificationToken = userService.validateVerificationToken(token);
        if (verificationToken.equals("valid")) {
            final User user = userService.getUser(token);

            authWithoutPassword(user);
            model.addAttribute("messageKey", "message.accountVerified");
            return new ModelAndView("redirect:/userlogin", model);
        }

        model.addAttribute("messageKey", "auth.message." + verificationToken);
        model.addAttribute("expired", "expired".equals(verificationToken));
        model.addAttribute("token", token);
        return new ModelAndView("redirect:/badUser", model);
    }

    @GetMapping("/console")
    public ModelAndView console(final HttpServletRequest request, final ModelMap model, @RequestParam("messageKey") final Optional<String> messageKey) {

        Locale locale = request.getLocale();
        messageKey.ifPresent( key -> {
                    String message = messages.getMessage(key, null, locale);
                    model.addAttribute("message", message);
                }
        );

        return new ModelAndView("console", model);
    }

    public void authWithoutPassword(User user) {
        Collection<Privilege> privileges = user.getRoles()
                .stream()
                .map(Role::getPrivileges)
                .flatMap(Collection::stream)
                .distinct()
                .collect(Collectors.toList());

        List<GrantedAuthority> authorities = privileges.stream()
                .map(p -> new SimpleGrantedAuthority(p.getName()))
                .collect(Collectors.toList());

        Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    // User activation - verification
    @GetMapping("/user/resendRegistrationToken")
    public GenericResponse resendRegistrationToken(final HttpServletRequest request, @RequestParam("token") final String existingToken) {
        final VerificationToken newToken = userService.generateNewVerificationToken(existingToken);
        final User user = userService.getUser(newToken.getToken());
        mailSender.send(constructResendVerificationTokenEmail(getAppUrl(request), request.getLocale(), newToken, user));
        return new GenericResponse(messages.getMessage("message.resendToken", null, request.getLocale()));
    }

    private SimpleMailMessage constructResendVerificationTokenEmail(final String contextPath, final Locale locale, final VerificationToken newToken, final User user) {
        final String confirmationUrl = contextPath + "/registrationConfirm?token=" + newToken.getToken();
        final String message = messages.getMessage("message.resendToken", null, locale);
        return constructEmail("Resend Registration Token", message + " \r\n" + confirmationUrl, user);
    }

    private SimpleMailMessage constructEmail(String subject, String body, User user) {
        final SimpleMailMessage email = new SimpleMailMessage();
        email.setSubject(subject);
        email.setText(body);
        email.setTo(user.getEmail());
        email.setFrom(env.getProperty("support.email"));
        return email;
    }

    // Change user password
    @PostMapping("/user/updatePassword")
//    @PreAuthorize("hasRole('READ_PRIVILEGE')")
    public GenericResponse changeUserPassword(final Locale locale, @Valid PasswordRequest passwordDto) {
        final User user = userService.findUserByEmail(((User) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getEmail());
        if (!userService.checkIfValidOldPassword(user, passwordDto.getOldPassword())) {
            throw new InvalidOldPasswordException();
        }
        userService.changeUserPassword(user, passwordDto.getNewPassword());
        return new GenericResponse(messages.getMessage("message.updatePasswordSuc", null, locale));
    }

    private String getAppUrl(HttpServletRequest request) {
        return "http://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();
    }

    private String getClientIP(HttpServletRequest request) {
        final String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty() || !xfHeader.contains(request.getRemoteAddr())) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }

}
