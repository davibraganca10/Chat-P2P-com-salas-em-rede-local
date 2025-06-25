# Chat-P2P-com-salas-em-rede-local
Sistema de Chat P2P com Tracker e Criptografia
Este é um projeto de um sistema de chat peer-to-peer (P2P) desenvolvido em Python. Ele utiliza um servidor central (Tracker) que gerencia usuários e salas, mas as mensagens são trocadas diretamente entre os peers de forma criptografada (ponta a ponta).

Funcionalidades
Autenticação de Usuários: Sistema de registro e login seguro com senhas hasheadas.

Criação de Salas: Usuários podem criar salas de chat para conversas em grupo.

Comunicação Direta P2P: As mensagens são enviadas diretamente entre os usuários, sem passar pelo servidor.

Criptografia de Ponta a Ponta: As mensagens são criptografadas com RSA-2048, garantindo que apenas o destinatário possa lê-las.

Mensagens em Grupo: Suporte para enviar mensagens para uma sala inteira.

Como Executar
Pré-requisitos
Python 3

Biblioteca cryptography

Para instalar a dependência, execute:

pip install cryptography

1. Iniciar o Tracker
O Tracker é o servidor central que gerencia as conexões e as salas. Ele deve ser o primeiro a ser iniciado.

python3 tracker.py

O Tracker ficará rodando e aguardando conexões na porta 12345.

2. Iniciar um Peer (Cliente)
Cada usuário deve iniciar sua própria instância do cliente (peer) em um terminal separado, especificando uma porta única para a comunicação P2P.

Usuário 1 (ex: Alice):

python3 peer.py 5001

Usuário 2 (ex: Bob):

python3 peer.py 5002

3. Usar o Chat
Após iniciar o peer, um menu de comandos será exibido.

register: Cria um novo usuário.

login: Entra com um usuário existente.

list_peers: Lista todos os usuários online.

list_rooms: Lista todas as salas de chat disponíveis.

create_room: Cria uma nova sala de chat.

join_room: Entra em uma sala existente.

leave_room: Sai da sala atual.

msg_room: Envia uma mensagem para todos na sala atual.

logout: Desconecta o usuário.

exit: Fecha a aplicação.

help: Mostra a lista de comandos.

Arquivos do Projeto
tracker.py: O código do servidor Tracker.

peer.py: O código do cliente Peer.

crypto_utils.py: Módulo com as funções de geração de chaves e criptografia/descriptografia.

tracker.db: Banco de dados SQLite criado pelo tracker para armazenar as informações dos usuários.