# Chat-P2P-com-salas-em-rede-local

## Sistema de Chat P2P com Tracker e Criptografia

### Contexto Acadêmico
Este projeto foi desenvolvido como estudo de redes de computadores, segurança e comunicação peer-to-peer (P2P) em Python. O sistema simula um ambiente de chat seguro, com autenticação, salas e troca de mensagens criptografadas ponta a ponta, sendo ideal para disciplinas de Redes, Sistemas Distribuídos ou Segurança da Informação.

---

### Objetivos
- Explorar conceitos de comunicação P2P e centralizada (via tracker)
- Implementar autenticação segura de usuários
- Garantir privacidade e confidencialidade das mensagens (criptografia RSA)
- Proporcionar experiência prática com sockets, threads e criptografia

---

### Funcionalidades
- **Autenticação de Usuários:** Registro e login com senhas hasheadas (armazenadas no tracker)
- **Criação e Gerenciamento de Salas:** Salas públicas e privadas (com senha)
- **Comunicação Direta P2P:** Mensagens trocadas diretamente entre peers, sem passar pelo servidor
- **Criptografia de Ponta a Ponta:** Mensagens protegidas com RSA-2048
- **Mensagens em Grupo e Privadas:** Suporte a chat em grupo (sala) e mensagens privadas
- **Gerenciamento de Conexões:** Listagem de peers conectados, salas e gerenciamento de entrada/saída

---

### Estrutura do Projeto
- `tracker.py`: Servidor central (tracker) responsável por autenticação, controle de salas e registro de peers
- `peer.py`: Cliente peer, interface de linha de comando para o usuário
- `crypto_utils.py`: Funções de geração de chaves, criptografia e descriptografia
- `tracker.db`: Banco de dados SQLite criado pelo tracker para armazenar usuários e salas
- `requirements.txt`: Dependências do projeto

---

### Pré-requisitos
- Python 3.8+
- Instalar dependências:

```bash
pip install -r requirements.txt
```

---

### Como Executar

#### 1. Iniciar o Tracker (Servidor Central)
O Tracker deve ser iniciado antes dos peers. Ele gerencia autenticação, salas e fornece informações de conexão.

```bash
python tracker.py
```

O Tracker ficará ouvindo na porta 12347 (ajuste conforme necessário no código).

#### 2. Iniciar um Peer (Cliente)
Cada usuário deve rodar o peer em um terminal separado, informando uma porta única para comunicação P2P:

```bash
python peer.py 5001  # Exemplo para Alice
python peer.py 5002  # Exemplo para Bob
```

#### 3. Utilização do Chat
Após iniciar o peer, utilize os comandos disponíveis:

- `register`: Criar novo usuário
- `login`: Fazer login
- `list_peers`: Listar usuários online
- `list_rooms`: Listar salas existentes
- `list_conn`: Listar peers conectados
- `create_room`: Criar nova sala (pública ou privada)
- `join_room`: Entrar em uma sala
- `leave_room`: Sair da sala atual
- `msg_room`: Enviar mensagem para todos na sala
- `msg`: Enviar mensagem privada para um usuário
- `kick`: (Dono) Expulsar usuário da sala
- `logout`: Sair da conta e fechar conexões
- `exit`: Fechar o programa
- `help`: Exibir ajuda

---

### Metodologia e Aspectos Técnicos
- **Sockets TCP:** Comunicação entre peers e tracker
- **Threads:** Permite múltiplas conexões simultâneas
- **Criptografia RSA:** Geração de chaves, criptografia e descriptografia de mensagens
- **Banco de Dados SQLite:** Persistência de usuários e salas
- **Tratamento de Erros:** Robustez contra falhas de conexão e desconexões inesperadas

---

### Sugestões de Discussão Acadêmica
- Limitações do modelo P2P com tracker centralizado
- Alternativas para autenticação e distribuição de chaves
- Possíveis ataques e vetores de ameaça
- Extensões: suporte a arquivos, interface gráfica, NAT traversal

---

### Licença
Este projeto é de uso acadêmico e livre para fins educacionais.