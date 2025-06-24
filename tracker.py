import socket
import threading
import json
import hashlib
import sqlite3

HOST = '0.0.0.0'
PORT = 12345
DB_PATH = 'tracker.db'

# Dicionário de peers ativos: { 'username': (conn, addr) }
active_peers = {}
# Dicionário de salas: { 'room_name': {'owner': 'username', 'members': {'user1', 'user2'}} }
rooms = {}
# Mapeia qual usuário está em qual sala: { 'username': 'room_name' }
user_current_room = {}

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        ''')
        conn.commit()

def send_json(conn, obj):
    msg = json.dumps(obj).encode()
    conn.sendall(len(msg).to_bytes(4, 'big') + msg)

def recv_json(conn):
    length_bytes = conn.recv(4)
    if not length_bytes:
        return None
    length = int.from_bytes(length_bytes, 'big')
    data = b''
    while len(data) < length:
        packet = conn.recv(length - len(data))
        if not packet:
            return None
        data += packet
    return json.loads(data.decode())

def close_room(room_name):
    """Fecha uma sala, removendo-a e desvinculando todos os seus membros."""
    print(f"[FECHAR SALA] Fechando a sala '{room_name}'.")
    if room_name in rooms:
        members_to_notify = rooms[room_name]['members']
        for member in members_to_notify:
            if member in user_current_room:
                del user_current_room[member]
        del rooms[room_name]

def handle_peer(conn, addr):
    user = None
    try:
        print(f"[CONEXÃO] Novo peer conectado de {addr}")
        while True:
            msg = recv_json(conn)
            if msg is None:
                break

            cmd = msg.get('cmd')
            
            if cmd == 'REGISTER':
                # (Lógica original mantida)
                username = msg.get('user')
                password = msg.get('password')
                if not username or not password:
                    send_json(conn, {"status": "error", "msg": "Usuário e senha são obrigatórios"})
                else:
                    with sqlite3.connect(DB_PATH) as conn_db:
                        c = conn_db.cursor()
                        c.execute('SELECT * FROM users WHERE username = ?', (username,))
                        if c.fetchone():
                            send_json(conn, {"status": "error", "msg": "Usuário já existe"})
                        else:
                            hash_pw = hashlib.sha256(password.encode()).hexdigest()
                            c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hash_pw))
                            conn_db.commit()
                            send_json(conn, {"status": "ok", "msg": f"Usuário '{username}' registrado com sucesso"})

            elif cmd == 'LOGIN':
                # (Lógica original mantida)
                username = msg.get('user')
                password = msg.get('password')
                if not username or not password:
                    send_json(conn, {"status": "error", "msg": "Credenciais inválidas"})
                    continue

                with sqlite3.connect(DB_PATH) as conn_db:
                    c = conn_db.cursor()
                    c.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
                    row = c.fetchone()
                    if not row:
                        send_json(conn, {"status": "error", "msg": "Usuário não existe"})
                    else:
                        hash_pw = hashlib.sha256(password.encode()).hexdigest()
                        if hash_pw == row[0]:
                            if username in active_peers:
                                send_json(conn, {"status": "error", "msg": "Usuário já logado"})
                            else:
                                user = username
                                # A porta do peer é a porta em que ele escuta, não a porta da conexão com o tracker
                                peer_listen_port = msg.get('port')
                                active_peers[user] = (conn, (addr[0], peer_listen_port))
                                send_json(conn, {"status": "ok", "msg": f"Bem vindo, {user}!"})
                                print(f"[LOGIN] {user} conectado de {addr} (ouvindo na porta {peer_listen_port})")
                        else:
                            send_json(conn, {"status": "error", "msg": "Senha incorreta"})

            elif cmd == 'LOGOUT':
                if user:
                    send_json(conn, {"status": "ok", "msg": "Desconectado"})
                    print(f"[LOGOUT] {user} desconectado")
                    break
                else:
                    send_json(conn, {"status": "error", "msg": "Você não está logado"})

            elif cmd == 'LIST_PEERS':
                if not user:
                    send_json(conn, {"status": "error", "msg": "Você precisa estar logado"})
                else:
                    peers_list = list(active_peers.keys())
                    send_json(conn, {"status": "ok", "peers": peers_list})

            elif cmd == 'LIST_ROOMS':
                if not user:
                    send_json(conn, {"status": "error", "msg": "Você precisa estar logado"})
                else:
                    rooms_list = list(rooms.keys())
                    send_json(conn, {"status": "ok", "rooms": rooms_list})

            elif cmd == 'CREATE_ROOM':
                room = msg.get('room')
                if not user:
                    send_json(conn, {"status": "error", "msg": "Você precisa estar logado para criar salas"})
                elif user in user_current_room:
                    send_json(conn, {"status": "error", "msg": f"Você já está na sala '{user_current_room[user]}'. Saia primeiro."})
                elif room in rooms:
                    send_json(conn, {"status": "error", "msg": "Sala já existe"})
                else:
                    rooms[room] = {'owner': user, 'members': {user}}
                    user_current_room[user] = room
                    print(f"[CRIAR SALA] {user} criou a sala '{room}'")
                    send_json(conn, {"status": "ok", "msg": f"Sala '{room}' criada e você foi adicionado a ela."})

            elif cmd == 'JOIN_ROOM':
                room = msg.get('room')
                if not user:
                    send_json(conn, {"status": "error", "msg": "Faça login primeiro"})
                elif user in user_current_room:
                    send_json(conn, {"status": "error", "msg": f"Você já está na sala '{user_current_room[user]}'. Saia primeiro."})
                elif room not in rooms:
                    send_json(conn, {"status": "error", "msg": "Sala não existe"})
                else:
                    members_info = []
                    for member in rooms[room]['members']:
                        if member in active_peers:
                            member_conn, member_addr = active_peers[member]
                            members_info.append({
                                "user": member,
                                "ip": member_addr[0],
                                "port": member_addr[1]
                            })
                    
                    rooms[room]['members'].add(user)
                    user_current_room[user] = room
                    print(f"[ENTRAR SALA] {user} entrou na sala '{room}'")

                    send_json(conn, {
                        "status": "ok",
                        "msg": f"Entrou na sala '{room}'",
                        "members": members_info
                    })
            
            elif cmd == 'LEAVE_ROOM':
                if not user:
                    send_json(conn, {"status": "error", "msg": "Você não está logado."})
                elif user not in user_current_room:
                    send_json(conn, {"status": "error", "msg": "Você não está em nenhuma sala."})
                else:
                    room_name = user_current_room[user]
                    del user_current_room[user]

                    if room_name in rooms:
                        rooms[room_name]['members'].remove(user)
                        print(f"[SAIR SALA] {user} saiu da sala '{room_name}'")
                        
                        is_owner = rooms[room_name]['owner'] == user
                        if is_owner:
                            send_json(conn, {"status": "ok", "msg": f"Você era o dono e saiu. A sala '{room_name}' foi fechada."})
                            close_room(room_name)
                        elif not rooms[room_name]['members']:
                            send_json(conn, {"status": "ok", "msg": f"Você era o último membro. A sala '{room_name}' foi fechada."})
                            close_room(room_name)
                        else:
                            send_json(conn, {"status": "ok", "msg": f"Você saiu da sala '{room_name}'."})
                    else:
                         send_json(conn, {"status": "ok", "msg": "Você saiu de uma sala que não existe mais."})

            else:
                send_json(conn, {"status": "error", "msg": "Comando desconhecido"})

    except Exception as e:
        print(f"[ERRO] {e}")

    finally:
        if user:
            if user in user_current_room:
                room_name = user_current_room[user]
                del user_current_room[user]
                if room_name in rooms:
                    if user in rooms[room_name]['members']:
                        rooms[room_name]['members'].remove(user)
                    
                    is_owner = rooms[room_name]['owner'] == user
                    if is_owner:
                        print(f"[DONO DESCONECTOU] Dono '{user}' da sala '{room_name}' desconectou.")
                        close_room(room_name)
                    elif not rooms[room_name]['members']:
                        print(f"[SALA VAZIA] A sala '{room_name}' ficou vazia e será fechada.")
                        close_room(room_name)

            if user in active_peers:
                del active_peers[user]
                print(f"[DESCONECTADO] {user} desconectado")
        conn.close()

def main():
    init_db()
    print(f"Tracker iniciando em {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_peer, args=(conn, addr), daemon=True).start()

if __name__ == '__main__':
    main()