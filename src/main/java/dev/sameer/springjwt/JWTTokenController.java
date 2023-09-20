package dev.sameer.springjwt;


import dev.sameer.springjwt.dto.JwtTokenDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
public class JWTTokenController {

    private JwtEncoder jwtEncoder;

    private Logger logger = LoggerFactory.getLogger(JWTTokenController.class);

    public JWTTokenController(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    @GetMapping("/authenticate")
    public JwtTokenDTO getJWTToken(Authentication authentication) {
        JwtTokenDTO jwtTokenDTO = new JwtTokenDTO();
      logger.debug(authentication.getPrincipal().toString());
         jwtTokenDTO.setToken(generateToken(authentication));
         return  jwtTokenDTO;
    }

    public String generateToken(Authentication authentication) {
        Instant now = Instant.now();
        String scope = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(" "));
        JwtClaimsSet claims = JwtClaimsSet.builder()
            .issuer("self")
            .issuedAt(now)
            .expiresAt(now.plus(1, ChronoUnit.HOURS))
            .subject(authentication.getName())
            .claim("scope", scope)
            .build();
        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

}
