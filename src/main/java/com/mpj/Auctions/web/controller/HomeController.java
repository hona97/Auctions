package com.mpj.Auctions.web.controller;

import com.mpj.Auctions.model.User;
import com.mpj.Auctions.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.WebUtils;

import java.security.Principal;
import java.util.Locale;
import java.util.Optional;

@Controller
public class HomeController {

    @Autowired
    private UserRepository repository;

    @Autowired
    private MessageSource messages;

    @GetMapping("/homepage")
    public ModelAndView homepage(final HttpServletRequest request, final ModelMap model, @RequestParam("messageKey" ) final Optional<String> messageKey, @RequestParam("error" ) final Optional<String> error,
                                 @RequestParam("user") final Optional<String> user) {
        Locale locale = request.getLocale();
        model.addAttribute("lang", locale.getLanguage());
        messageKey.ifPresent(key -> {
                    String message = messages.getMessage(key, null, locale);
                    model.addAttribute("message", message);
                }
        );
        user.ifPresent(u -> {
            User usr = repository.findByEmail(u);
            model.addAttribute("user", usr);
        });
        error.ifPresent(e ->  model.addAttribute("error", e));

//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//        User usr = (User) auth.getPrincipal();
//        model.addAttribute("user", usr);

        return new ModelAndView("homepage", model);
    }
}
