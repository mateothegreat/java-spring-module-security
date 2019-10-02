package platform.security;

import org.springframework.beans.factory.annotation.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.*;
import org.springframework.stereotype.*;
import platform.api.logging.*;
import platform.api.users.*;

import java.util.*;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private LogsService logsService;

    @Autowired
    UsersRepository usersRepository;

    @Autowired
    UsersService usersService;

    @Override
    public Authentication authenticate(Authentication auth) throws AuthenticationException {

        String username = auth.getName();
        String password = auth.getCredentials().toString();

        Optional<User> user = usersRepository.getByEmail(username);

        if (!user.isPresent()) {

            throw new BadCredentialsException("User doesn't exist");

        } else if (user.get().getPassword().equals(password)) {

            logsService.createForUser(user.get().getId(), "LOGIN_SUCCESSFUL", "User logged in.");

            usersService.setStampLastLoginByEmail(user.get().getEmail());

            return new UsernamePasswordAuthenticationToken(username, password, Collections.emptyList());

        } else {

            logsService.createForUser(user.get().getId(), "LOGIN_BAD_PASSWORD", "The user tried to login with the password \"" + password + "\" and failed.");

            throw new BadCredentialsException("External system authentication failed");

        }

    }

    @Override
    public boolean supports(Class<?> auth) {

        return auth.equals(UsernamePasswordAuthenticationToken.class);

    }

}
