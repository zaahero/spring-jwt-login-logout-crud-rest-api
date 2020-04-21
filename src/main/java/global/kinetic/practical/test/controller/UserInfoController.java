package global.kinetic.practical.test.controller;


import global.kinetic.practical.test.config.JwtToken;
import global.kinetic.practical.test.exceptions.ValidationException;
import global.kinetic.practical.test.model.UserInfo;
import global.kinetic.practical.test.repository.UserInfoRepository;
import global.kinetic.practical.test.service.JwtUserDetailsService;
import io.jsonwebtoken.ExpiredJwtException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;


@Tag(name = "UserInfo", description = "API for userinfo")
@RestController
@RequestMapping("/api")
public class UserInfoController {

    @Autowired
    private UserInfoRepository userInfoRepository;

    @Autowired
    private JwtUserDetailsService jwtUserDetailsService;

    @Autowired
    private JwtToken jwtToken;

//    private HashData hashData = new HashData();

    public UserInfoController(UserInfoRepository userInfoRepository) {
        this.userInfoRepository = userInfoRepository;
    }


    @Operation(summary = "Create a new user", description = "Create a new user with username , phone and password", tags = { "userinfo" })
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "successful operation",
                    content = @Content(schema = @Schema(implementation = UserInfo.class))) })
    @PostMapping("/user")
    public Boolean create(@RequestBody UserInfo body) throws NoSuchAlgorithmException {
        String username = body.getUsername();
        if (userInfoRepository.existsByUsername(username)){

            throw new ValidationException("Username already existed");

        }

        String password = body.getPassword();
        String encodedPassword = new BCryptPasswordEncoder().encode(password);
//        String hashedPassword = hashData.get_SHA_512_SecurePassword(password);
        int phone = body.getPhone();
        userInfoRepository.save(new UserInfo(username, encodedPassword, phone));
        return true;
    }

//    //implement get users here
    @Operation(summary = "Find all Users", description = "All users", tags = { "userInfo" })
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "successful operation",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = UserInfo.class)))) })
    @GetMapping("/users")
    public List<UserInfo> index(){
        return userInfoRepository.findAll();
    }

    @Operation(summary = "Find all Users", description = "All users", tags = { "userInfo" })
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "successful operation",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = UserInfo.class)))) })
    @GetMapping("/validusers")
    public String getNumberOfValidUsers(){


        String token = null;
        String username = null;
        List<UserInfo> users = userInfoRepository.findAll();


        for(UserInfo user : users){
                token = user.getToken();
                username = user.getUsername();
                UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(username);

            try {

                if (jwtToken.validateToken(token, userDetails).equals(false))
                    user.setValid(false);

            } catch (IllegalArgumentException e) {

                System.out.println("Unable to get JWT Token");
                user.setValid(false);

            } catch (ExpiredJwtException e) {

                System.out.println("JWT Token has expired");
                user.setValid(false);
            }

            userInfoRepository.save(user);
        }

        return "The number of valid users logged in is " +userInfoRepository.findAllByValidTrue().size();
    }

}
