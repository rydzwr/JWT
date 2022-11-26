package com.rydzwr.SpringJWT.service;

import com.rydzwr.SpringJWT.model.Role;
import com.rydzwr.SpringJWT.model.User;
import com.rydzwr.SpringJWT.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@RequiredArgsConstructor
public class DataLoader implements ApplicationRunner {
    private final UserRepository userRepository;
    private final UserService userService;

    public void run(ApplicationArguments args) {
        userRepository.deleteAll();
        User admin = new User();
        admin.setUsername("admin");
        admin.setPassword("admin");
        admin.setUserRoles(new ArrayList<Role>(List.of(Role.ROLE_ADMIN)));

        userService.save(admin);

        User user = new User();
        user.setUsername("user");
        user.setPassword("user");
        user.setUserRoles(new ArrayList<Role>(List.of(Role.ROLE_USER)));

        userService.save(user);
    }

}
