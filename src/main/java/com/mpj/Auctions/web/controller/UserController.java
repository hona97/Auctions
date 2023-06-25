package com.mpj.Auctions.web.controller;

import com.mpj.Auctions.email.EmailSender;
import com.mpj.Auctions.model.PasswordResetToken;
import com.mpj.Auctions.model.User;
import com.mpj.Auctions.repository.UserRepository;
import com.mpj.Auctions.security.ActiveUserStore;
import com.mpj.Auctions.service.ISecurityUserService;
import com.mpj.Auctions.service.IUserService;
import com.mpj.Auctions.web.dto.EmailRequest;
import com.mpj.Auctions.web.dto.PasswordRequest;
import com.mpj.Auctions.web.util.GenericResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.core.env.Environment;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.ModelAndView;

import java.util.Locale;
import java.util.Optional;

@Controller
@RequiredArgsConstructor
public class UserController {

    @Autowired
    ActiveUserStore activeUserStore;

    @Autowired
    IUserService userService;

    @Autowired
    private UserRepository repository;

    @Autowired
    private MessageSource messages;

    @Autowired
    private Environment env;

    @Autowired
    private final EmailSender emailSender;

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private ISecurityUserService securityUserService;

    @GetMapping("/loggedUsers")
    public String getLoggedUsers(final Locale locale, final Model model) {
        model.addAttribute("users", activeUserStore.getUsers());
        return "users";
    }

    @GetMapping("/loggedUsersFromSessionRegistry")
    public String getLoggedUsersFromSessionRegistry(final Locale locale, final Model model) {
        model.addAttribute("users", userService.getUsersFromSessionRegistry());
        return "users";
    }

    @GetMapping("/user/account")
    public ModelAndView profile(final HttpServletRequest request, final ModelMap model,
                                 @RequestParam("user") final Optional<String> user) {
        Locale locale = request.getLocale();
        model.addAttribute("lang", locale.getLanguage());

        user.ifPresent(u -> {
            User usr = repository.findByEmail(u);
            model.addAttribute("user", usr);
        });

        return new ModelAndView("layoutprofile", model);
    }

    @GetMapping("/forgetPassword")
    public ModelAndView forgetPassword(final HttpServletRequest request,
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

        error.ifPresent(e -> {
                    String message = messages.getMessage(e, null, locale);
                    model.addAttribute("error", message);
                }
        );
        return new ModelAndView("forgetPassword", model);
    }

    // Reset password
    @PostMapping("/user/resetPasswordMail")
    public ModelAndView resetPassword(final HttpServletRequest request, @Valid final EmailRequest emailRequest, final ModelMap model) {
        final User user = userService.findUserByEmail(emailRequest.getEmail());

        if (user == null) {
            model.addAttribute("error","auth.message.invalidUser");
            return new ModelAndView("redirect:/forgetPassword", model);
        }
        PasswordResetToken token = userService.createPasswordResetTokenForUser(user);
        mailSender.send(constructResetTokenEmail(getAppUrl(request), request.getLocale(), token.getToken(), user));
        model.addAttribute("messageKey","message.resetPasswordEmail");
        return new ModelAndView("redirect:/forgetPassword", model);
//        return new GenericResponse(messages.getMessage("message.resetPasswordEmail", null, request.getLocale()));
    }

    @GetMapping("/user/resetPasswordForm")
    public ModelAndView changePassword(final ModelMap model, @RequestParam("token") final String token, @RequestParam("user") final Optional<String> userEmail) {
        final String result = securityUserService.validatePasswordResetToken(token);

        if(result != null) {
            String error = "auth.message." + result;
            model.addAttribute("error", error);
            return new ModelAndView("redirect:/forgetPassword", model);
        } else {
            userEmail.ifPresent(e -> {
                User usr = repository.findByEmail(e);
                model.addAttribute("user", usr);
            });

            model.addAttribute("token", token);
            return new ModelAndView("resetPassword", model);
        }
    }

    // Save password
    @PostMapping("/user/savePassword")
    public ModelAndView savePassword(final Locale locale, @Valid final PasswordRequest passwordRequest, final ModelMap model) {

        final String result = securityUserService.validatePasswordResetToken(passwordRequest.getToken());

        if(result != null) {
            return new ModelAndView("redirect:/user/resetPasswordForm?token=" + passwordRequest.getToken());
        }

        Optional<User> user = userService.getUserByPasswordResetToken(passwordRequest.getToken());
        if(user.isPresent()) {
            userService.changeUserPassword(user.get(), passwordRequest.getNewPassword());
            model.addAttribute("messageKey", "message.resetPasswordSuc");
            return new ModelAndView("redirect:/userlogin", model);
        } else {
            model.addAttribute("messageKey", "auth.message.invalid");
            return new ModelAndView("redirect:/forgetPassword", model);
        }
    }

    private SimpleMailMessage constructResetTokenEmail(final String contextPath, final Locale locale, final String token, final User user) {
        final String url = contextPath + "/user/resetPasswordForm?token=" + token + "&user=" + user.getEmail();
        final String message = messages.getMessage("message.resetPassword", null, locale);
        return constructEmail("Reset Password", message + " \r\n" + url, user);
    }

    private SimpleMailMessage constructEmail(String subject, String body, User user) {
        final SimpleMailMessage email = new SimpleMailMessage();
        email.setSubject(subject);
        email.setText(body);
        email.setTo(user.getEmail());
        email.setFrom(env.getProperty("support.email"));
        return email;
    }

    private String getAppUrl(HttpServletRequest request) {
        return "http://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();
    }
}
