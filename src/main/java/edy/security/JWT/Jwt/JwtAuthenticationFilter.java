package edy.security.JWT.Jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//Para decirle a Spring que es un Bean
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    //Este metodo manejara todos los filtros del toquen
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        //1. Obtener el token del request
        final String token = getTokenFromRequest(request);

        //Si el token es nulo le devolvemos el control a la cadena de filtros
        if(token == null) {
            filterChain.doFilter(request, response);
            return;
        }
        filterChain.doFilter(request, response);

    }

    private String getTokenFromRequest(HttpServletRequest request) {
        //Intentamos coger del header la identificacion que debe empezar por "Bearer"
        //Accedemos al header a traves del request
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        //Necesitamos obtener el token sin la palabra Bearer
        //Vamos a usar la libreria de StringUtils para comprobar que
        //el token tiene la palabra Authorization Y que el token empieza por Bearer
        if(StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }
}
