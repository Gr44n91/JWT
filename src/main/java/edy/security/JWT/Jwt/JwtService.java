package edy.security.JWT.Jwt;

import edy.security.JWT.User.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;

@Service
public class JwtService {

    private static final String SECRET_KEY = "51516521DF62365262F262695G2626VTVSDF262326562FSD62523265962RF";
    //Metodo para enviar el token al servicio
    public String getToken(UserDetails user) {
        return getToken(new HashMap<>(), user);
    }
    //Metodo para generar el TOKEN
    private String getToken(HashMap<String, Object> extraClaims, UserDetails user){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();

    }
    //Metodo para generar la Key
    private Key getKey(){
        //Vamos a pasar la SECRET KEY A BASE64 con el metodo Decoders.BASE64.decode(KEY)
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
