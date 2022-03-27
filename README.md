# Spring Security JWT Demo

Um exemplo de autenticação e autorização utilizando JWT, para utilizar como referêrencia em projetos futuros.

Esta aplicação conta com um banco de dados em memória H2 para armazenamento temporario dos usuários, onde um novo banco é instânciado em cada execução, o banco pode ser acesso no endpoint /h2-console.

## Usuários

Usuário 01
- username: leonardo
- password: senha123
- roles: COMMON

Usuário 02
- username: claudia
- password: 123senha
- roles: COMMON, ADMIN

###### Observação: As senhas são critografadas utilizando o BCryptPasswordEncoder.

## Paramêtros

Para que a autenticação funcione corretamente é necessario passar 3 parametros para a aplicação, eles sendo:

- ``application.jwt.secret-key`` Chave secreta para assinatura dos tokens;

- ``application.jwt.token-prefix`` Prefixo que será verificado ao autenticar os tokens;

- ``application.jwt.token-expiration-after-days`` Tempo dos tokens em dias.

## End-points

- ``POST`` /login -  Responsável por gerar o token de autenticação para o usuário.
    - Requerido body na seguinte estrutura:
    ~~~json
    {
        "username" : "leonardo",
        "password" : "senha123"
    }
    ~~~
- ``GET`` /ping -  Retorna uma string, apenas usuários com role de ADMIN tem acesso.