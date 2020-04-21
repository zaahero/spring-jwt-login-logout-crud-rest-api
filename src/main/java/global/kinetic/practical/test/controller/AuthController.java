package global.kinetic.practical.test.controller;


import global.kinetic.practical.test.config.JwtToken;
import global.kinetic.practical.test.model.JwtRequest;
import global.kinetic.practical.test.model.JwtResponse;
import global.kinetic.practical.test.model.UserInfo;
import global.kinetic.practical.test.repository.UserInfoRepository;
import global.kinetic.practical.test.service.JwtUserDetailsService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

@RestController
@CrossOrigin
@RequestMapping("/api")
@Tag(name = "Authentication", description = "API for authenticate")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtToken jwtToken;

    @Autowired
    private JwtUserDetailsService jwtUserDetailsService;

    @Autowired
    private UserInfoRepository userInfoRepository;

    @Autowired
    private DefaultTokenServices tokenServices;


    @Operation(summary = "Authenticate", description = "Authenticate user credentials", tags = { "authenticate" })
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "successful operation",
                    content = @Content(schema = @Schema(implementation = JwtResponse.class))) })
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtRequest authenticationRequest, HttpServletRequest request, HttpServletResponse response,
                                                       Authentication authentication) throws Exception {

        authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());

        final UserDetails userDetails = jwtUserDetailsService
                .loadUserByUsername(authenticationRequest.getUsername());

        final String token = jwtToken.generateToken(userDetails);

        UserInfo userInfo = userInfoRepository.findByUsername(authenticationRequest.getUsername());
        userInfo.setToken(token);
        userInfo.setValid(true);
        userInfoRepository.save(userInfo);

        return ResponseEntity.ok(new JwtResponse(token));
    }

    private void authenticate(String username, String password) throws Exception {

        try {
            authenticationManager.authenticate( new UsernamePasswordAuthenticationToken(username, password));

        } catch (DisabledException e) {

            throw new Exception("USER_DISABLED", e);

        } catch (BadCredentialsException e) {

            throw new Exception("INVALID_CREDENTIALS", e);

        }

    }


    @RequestMapping(value="/logout/{id}", method = RequestMethod.POST)
    @ResponseBody
    public ResponseEntity<?> logout(@PathVariable("id") int id) throws Exception {

        Optional<UserInfo> userInfo = this.userInfoRepository.findById(id);

        userInfo.get().setValid(false);
        String token = userInfo.get().getToken();
        userInfoRepository.save(userInfo.get());

        return ResponseEntity.ok(token);
    }

//    @RequestMapping(method = RequestMethod.GET, path = "/log")
//    @ResponseStatus(HttpStatus.OK)
//    public String getLogoutPage(HttpServletRequest request, HttpServletResponse response){
//
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        authentication.setAuthenticated(false);
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//        SecurityContextLogoutHandler handler = new SecurityContextLogoutHandler();
//
//            handler.logout(request, response, authentication);
//            handler.setClearAuthentication(true);
//            handler.setInvalidateHttpSession(true);
//        return "logged out";
//    }
}
