# Spring Security JWT Demo

Um exemplo de autenticação e autorização utilizando JWT, para utilizar como referência em projetos futuros.

Esta aplicação conta com um banco de dados em memória H2 para armazenamento temporário dos usuários, onde um novo banco é instanciado em cada execução, o banco pode ser acesso no endpoint /h2-console.

## Usuários

Usuário 01
- username: leonardo
- password: senha123
- roles: COMMON

Usuário 02
- username: claudia
- password: 123senha
- roles: COMMON, ADMIN

###### Observação: As senhas são criptografadas utilizando o BCryptPasswordEncoder.

## Parâmetros

Para que a autenticação funcione corretamente é necessário passar 4 parâmetros para a aplicação, eles sendo:

- ``application.jwt.secret-key`` Chave secreta para assinatura dos tokens;

- ``application.jwt.token-prefix`` Prefixo que será verificado ao autenticar os tokens;

- ``application.jwt.token-expiration-after-days`` Tempo dos tokens em dias;

- ``application.jwt.authorization-header-name`` Nome do header que o endpoint /login utilizará para enviar o token.

## End-points

- ``POST`` /login - Responsável por gerar o token de autenticação para o usuário.
    - Requerido body na seguinte estrutura:
    ~~~json
    {
        "username" : "leonardo",
        "password" : "senha123"
    }
    ~~~
    - Se as crendênciais estiverem corretas, o status da resposta será 200 e o token vai ser enviado em um header chamado authorization, caso contrário a requisição receberá uma resposta com código 401.

> Todos os endpoints abaixo necessitam de autenticação, é necessário enviar um header chamado de authorization com o valor sendo o próprio token recebido ao enviar suas credênciais no endpoint /login.

- ``GET`` /auth/refresh-token - Retorna um token atualizado com uma nova data de expiração
- ``GET`` /ping - Retorna os dados do usuário que fez a requisição, apenas usuários com role de ADMIN tem acesso.