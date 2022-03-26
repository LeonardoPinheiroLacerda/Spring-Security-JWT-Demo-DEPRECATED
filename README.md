# Spring Security JWT Demo

Um exemplo de autenticação e autorização utilizando JWT, para utilizar como referêrencia em projetos futuros.

Esta aplicação conta com um banco de dados em memória H2 para armazenamento temporario dos usuários, onde um novo banco é instânciado em cada execução, o banco pode ser acesso no endpoint /h2-console.

## Usuários

Usuário 01
- username: leonardo
- password: senha123

Usuário 02
- username: claudia
- password: 123senha

###### Observação: As senhas são critografadas utilizando o BCryptPasswordEncoder.