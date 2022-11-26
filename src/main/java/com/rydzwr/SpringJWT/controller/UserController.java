package com.rydzwr.SpringJWT.controller;

import javax.servlet.http.HttpServletRequest;

import com.rydzwr.SpringJWT.model.UserDataResponse;
import com.rydzwr.SpringJWT.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /*
    @PostMapping("/login")
    public String login(@RequestParam(value = "username") String username, @RequestParam(value = "password") String password) {
        log.info("Username: -->  {}", username);
        log.info("Password: -->  {}", password);
        return userService.login(username, password);
    }

     */

    @GetMapping("/data/user")
    @PreAuthorize("hasRole('ROLE_USER')")
    public UserDataResponse home() {
        return new UserDataResponse("user public data");
    }

    @GetMapping("/data/admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public UserDataResponse admin() {
        return new UserDataResponse("admin only data");
    }

    @GetMapping("/token/refresh")
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
    public String refresh(HttpServletRequest req) {
        return userService.refreshToken(req.getRemoteUser());
    }

}
