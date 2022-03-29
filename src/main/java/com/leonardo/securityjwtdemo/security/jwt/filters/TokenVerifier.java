package com.leonardo.securityjwtdemo.security.jwt.filters;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.common.base.Strings;
import com.leonardo.securityjwtdemo.model.AppUser;
import com.leonardo.securityjwtdemo.security.jwt.JwtConfig;
import com.leonardo.securityjwtdemo.security.users.AppUserDetails;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.AllArgsConstructor;

@AllArgsConstructor

//Classe responsável por válidar o token enviado pelo usuário afim de acessar os recursos da aplicação
public class TokenVerifier extends OncePerRequestFilter {
   
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
        HttpServletResponse response, 
        FilterChain filterChain
    ) throws ServletException, IOException {
        
        //Salva o header de autorização em uma variavel
        String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeaderName());
        
        //Verifica se o header de autorização está preenchido e se o prefixo está correto.
        if(Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())){
            filterChain.doFilter(request, response);
            return;
        }

        //Remove o prefixo mantendo apenas o token
        String token = authorizationHeader.replace(jwtConfig.getTokenPrefix() , "");
        
        try{
            //Recebe o corpo do token JWS
            Claims body = getClaims(token).getBody();

            //Convente os dados do JWS em um objeto do tipo Authentication
            Authentication authentication = checkAuthenticationFromJwsBody(body);

            //Insere o objeto de autenticação no contexto de segurança do Spring
            SecurityContextHolder.getContext().setAuthentication(authentication);

            //Da continuidade ao processo de autorização
            filterChain.doFilter(request, response);
        }catch(JwtException e){
            //Exceção lançada ao receber um JWS inválido.
            //Observação: Como se trata de uma aplicação com fins de demonstração, essa exceção não é tratada,
            //logo a requisição que alcançar esse ponto receberá código 500 como resposta. Aconselho tratar essa exceção para retornar um código 401
            throw new IllegalStateException("Token " + token + " cannot be trusted");
        }
    }
    

    protected Jws<Claims> getClaims(String token){
        //Extrai o body do token
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token);
    }

    protected Authentication checkAuthenticationFromJwsBody(Claims body){

        //Recebe o username presente no atributo subject
        String username = body.getSubject();

        //Recebe as autoridades do usuário e os salva em uma lista
        @SuppressWarnings("unchecked")
        List<Map<String, String>> authorities = (List<Map<String, String>>) body.get("authorities");

        //Converte a lista de autoridades para um conjunto de SimpleGrantedAuthorities.
        Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities
            .stream()
            .map(m -> new SimpleGrantedAuthority(m.get("authority")))
            .collect(Collectors.toSet());

        
        //Com base no username presente no JWS, o sistema busca o usuário correspondente no banco de dados.
        AppUserDetails userDetails = (AppUserDetails) userDetailsService.loadUserByUsername(username);
        AppUser user = userDetails.getUser();

        //Constrói o objeto de autenticação com os dados extraídos a cima
        Authentication authentication = new UsernamePasswordAuthenticationToken(
            user, 
            user.getPassword(),
            simpleGrantedAuthorities
        );

        return authentication;
    }
}
