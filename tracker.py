import socket
import threading
import json
import hashlib
import sqlite3

HOST = '0.0.0.0'
PORT = 12345
DB_PATH = 'tracker.db'

active_peers = {}
rooms = {}
user_current_room = {}
data_lock = threading.Lock()

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
    try:
        msg = json.dumps(obj).encode()
        conn.sendall(len(msg).to_bytes(4, 'big') + msg)
    except (ConnectionResetError, BrokenPipeError):
        pass

def recv_json(conn):
    try:
        length_bytes = conn.recv(4)
        if not length_bytes: return None
        length = int.from_bytes(length_bytes, 'big')
        data = b''
        while len(data) < length:
            packet = conn.recv(length - len(data))
            if not packet: return None
            data += packet
        return json.loads(data.decode())
    except (ConnectionResetError, json.JSONDecodeError, OSError):
        return None

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
                username = msg.get('user')
                password = msg.get('password')
                if not username or not password: send_json(conn, {"status": "error", "msg": "Usuário e senha são obrigatórios"}); continue
                with sqlite3.connect(DB_PATH) as conn_db:
                    c = conn_db.cursor()
                    c.execute('SELECT * FROM users WHERE username = ?', (username,))
                    if c.fetchone(): send_json(conn, {"status": "error", "msg": "Usuário já existe"}); continue
                    hash_pw = hashlib.sha256(password.encode()).hexdigest()
                    c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hash_pw))
                    conn_db.commit()
                    send_json(conn, {"status": "ok", "msg": f"Usuário '{username}' registrado com sucesso"})
            elif cmd == 'LOGIN':
                username = msg.get('user')
                password = msg.get('password')
                if not username or not password: send_json(conn, {"status": "error", "msg": "Credenciais inválidas"}); continue
                with sqlite3.connect(DB_PATH) as conn_db:
                    c = conn_db.cursor()
                    c.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
                    row = c.fetchone()
                    if not row: send_json(conn, {"status": "error", "msg": "Usuário não existe"}); continue
                    hash_pw = hashlib.sha256(password.encode()).hexdigest()
                    if hash_pw == row[0]:
                        if username in active_peers: send_json(conn, {"status": "error", "msg": "Usuário já logado"}); continue
                        user = username
                        peer_listen_port = msg.get('port')
                        with data_lock: active_peers[user] = (conn, (addr[0], peer_listen_port))
                        send_json(conn, {"status": "ok", "msg": f"Bem vindo, {user}!"})
                        print(f"[LOGIN] {user} conectado de {addr} (ouvindo na porta {peer_listen_port})")
                    else:
                        send_json(conn, {"status": "error", "msg": "Senha incorreta"})
            
            if not user:
                if cmd not in ['LOGIN', 'REGISTER']: send_json(conn, {"status": "error", "msg": "Você precisa estar logado."})
                continue
            
            if cmd == 'LOGOUT':
                send_json(conn, {"status": "ok", "msg": "Desconectado"})
                break 
        
            elif cmd == 'LIST_PEERS':
                with data_lock: peers_list = list(active_peers.keys())
                send_json(conn, {"status": "ok", "peers": peers_list})
            elif cmd == 'LIST_ROOMS':
                with data_lock:
                    rooms_info = []
                    for name, data in rooms.items():
                        room_type = "Privada" if data['password_hash'] else "Pública"
                        rooms_info.append(f"{name} ({room_type}, {len(data['members'])} membros)")
                send_json(conn, {"status": "ok", "rooms": rooms_info})
            elif cmd == 'CREATE_ROOM':
                room = msg.get('room')
                password = msg.get('password') 
                with data_lock:
                    if user in user_current_room: send_json(conn, {"status": "error", "msg": f"Você já está na sala '{user_current_room[user]}'. Saia primeiro."}); continue
                    if room in rooms: send_json(conn, {"status": "error", "msg": "Sala já existe"}); continue
                    password_hash = hashlib.sha256(password.encode()).hexdigest() if password else None
                    rooms[room] = {'owner': user, 'members': {user}, 'password_hash': password_hash}
                    user_current_room[user] = room
                    print(f"[CRIAR SALA] {user} criou a sala '{room}'")
                    send_json(conn, {"status": "ok", "msg": f"Sala '{room}' criada."})
            elif cmd == 'JOIN_ROOM':
                room = msg.get('room')
                password = msg.get('password')
                with data_lock:
                    if user in user_current_room: send_json(conn, {"status": "error", "msg": f"Você já está na sala '{user_current_room[user]}'. Saia primeiro."}); continue
                    if room not in rooms: send_json(conn, {"status": "error", "msg": "Sala não existe"}); continue
                    room_data = rooms[room]
                    if room_data['password_hash']:
                        if not password or hashlib.sha256(password.encode()).hexdigest() != room_data['password_hash']:
                            send_json(conn, {"status": "error", "msg": "Senha incorreta."}); continue
                    members_info = []
                    for member in room_data['members']:
                        if member in active_peers:
                            _, member_addr = active_peers[member]
                            members_info.append({"user": member, "ip": member_addr[0], "port": member_addr[1]})
                    room_data['members'].add(user)
                    user_current_room[user] = room
                    print(f"[ENTRAR SALA] {user} entrou na sala '{room}'")
                    send_json(conn, { "status": "ok", "msg": f"Entrou na sala '{room}'", "members": members_info })
            elif cmd == 'KICK_PEER':
                room_name = msg.get('room')
                target_user = msg.get('target_user')
                with data_lock:
                    if room_name not in rooms: send_json(conn, {"status": "error", "msg": "Sala não existe mais."}); continue
                    if rooms[room_name]['owner'] != user: send_json(conn, {"status": "error", "msg": "Você não é o dono da sala."}); continue
                    if target_user not in rooms[room_name]['members']: send_json(conn, {"status": "error", "msg": "Usuário não está nesta sala."}); continue
                    if target_user == user: send_json(conn, {"status": "error", "msg": "Você não pode se expulsar."}); continue
                    rooms[room_name]['members'].remove(target_user)
                    del user_current_room[target_user]
                    if target_user in active_peers:
                        target_conn, _ = active_peers[target_user]
                        send_json(target_conn, {"event": "YOU_WERE_KICKED", "room": room_name, "by": user})
                    send_json(conn, {"status": "ok", "msg": f"Usuário {target_user} foi expulso."})
                    print(f"[KICK] {user} expulsou {target_user} da sala {room_name}")
            
            elif cmd == 'GET_PEER_INFO':
                target_user = msg.get('target_user')
                with data_lock:
                    if target_user not in active_peers:
                        send_json(conn, {"status": "error", "msg": "Usuário alvo não está online ou não existe."})
                    else:
                        _target_conn, target_addr = active_peers[target_user]
                        send_json(conn, {
                            "status": "ok",
                            "user": target_user,
                            "ip": target_addr[0],
                            "port": target_addr[1]
                        })

            elif cmd == 'LEAVE_ROOM':
                with data_lock:
                    if user not in user_current_room:
                        send_json(conn, {"status": "error", "msg": "Você não está em nenhuma sala."}); continue
                    
                    room_name = user_current_room[user]

                    if room_name in rooms:
                        is_owner = rooms[room_name]['owner'] == user
                        
                        if is_owner:
                            print(f"[FECHAR SALA] Dono '{user}' está saindo da sala '{room_name}'. Notificando membros.")
                            
                            #quando o dono sai da sala, acaba  a sala e manda aviso pros membros
                            members_to_close = list(rooms[room_name]['members'])
                            
                            for member in members_to_close:
                                if member != user: # Não envia o aviso a si mesmo
                                    if member in active_peers:
                                        peer_conn, _ = active_peers[member]
                                        send_json(peer_conn, {"event": "ROOM_CLOSED", "room": room_name})
                         
                                if member in user_current_room:
                                    del user_current_room[member]
                            
                            #aqui efetivamente fecha a sala
                            del rooms[room_name]
                            
                            
                            send_json(conn, {"status": "ok", "msg": f"Você era o dono e saiu. A sala '{room_name}' foi fechada."})
                        else:
                            # Se não é o dono, segue o jogo
                            rooms[room_name]['members'].remove(user)
                            del user_current_room[user]
                            send_json(conn, {"status": "ok", "msg": f"Você saiu da sala '{room_name}'."})
                            print(f"[SAIR SALA] {user} saiu da sala '{room_name}'")
                    else:
                        del user_current_room[user]
                        send_json(conn, {"status": "ok", "msg": "Você saiu de uma sala que não existe mais."})

    except Exception as e:
        print(f"[ERRO] {e}")

    finally:
        with data_lock:
            if user:
                if user in user_current_room:
                    room_name = user_current_room[user]
                    if room_name in rooms and rooms[room_name]['owner'] == user:
                        print(f"[DONO DESCONECTOU] Dono '{user}' da sala '{room_name}' desconectou. Fechando sala.")
                        # fechando a sala para perda de conexão do dono
                        members_to_close = list(rooms[room_name]['members'])
                        for member in members_to_close:
                            if member != user and member in active_peers:
                                peer_conn, _ = active_peers[member]
                                send_json(peer_conn, {"event": "ROOM_CLOSED", "room": room_name})
                            if member in user_current_room:
                                del user_current_room[member]
                        del rooms[room_name]

                    elif room_name in rooms and user in rooms[room_name]['members']:
                         rooms[room_name]['members'].remove(user)
                
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