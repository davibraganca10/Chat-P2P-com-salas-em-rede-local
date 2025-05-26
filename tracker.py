import socket
import threading
import json
import hashlib

HOST = '0.0.0.0' 
PORT = 12345      

#banco de usuários 
users_db = {
    'alice': hashlib.sha256('alicepass'.encode()).hexdigest(),
    'bob': hashlib.sha256('bobpass'.encode()).hexdigest(),
    'carol': hashlib.sha256('carolpass'.encode()).hexdigest()
}

active_peers = {} 
rooms = {}         


def send_json(conn, obj):
    msg = json.dumps(obj).encode()
    # protocolo simples: envia tamanho + dados para delimitar mensagem
    conn.sendall(len(msg).to_bytes(4, 'big') + msg)


def recv_json(conn):
    # lê 4 bytes do tamanho
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


def handle_peer(conn, addr):
    user = None
    try:
        while True:
            msg = recv_json(conn)
            if msg is None:
                break

            cmd = msg.get('cmd')
            if cmd == 'LOGIN':  #fazer login
                username = msg.get('user')
                password = msg.get('password')
                if username in users_db:  #se o user existe
                    hash_pw = hashlib.sha256(password.encode()).hexdigest()
                    if hash_pw == users_db[username]:
                        if username in active_peers:  #checa se o user ja ta logado
                            send_json(conn, {"status": "error", "msg": "Usuário já logado"})
                        else:              #loga o usuario
                            user = username
                            active_peers[user] = (conn, addr)
                            send_json(conn, {"status": "ok", "msg": f"Bem vindo, {user}!"})
                            print(f"[LOGIN] {user} conectado de {addr}")
                    else:
                        send_json(conn, {"status": "error", "msg": "Senha incorreta"})
                else:
                    send_json(conn, {"status": "error", "msg": "Usuário não existe"})

            elif cmd == 'LOGOUT':   #fazer logout
                if user:
                    del active_peers[user]
                    send_json(conn, {"status": "ok", "msg": "Desconectado"})
                    print(f"[LOGOUT] {user} desconectado")
                    break
                else:
                    send_json(conn, {"status": "error", "msg": "Você não está logado"})

            elif cmd == 'LIST_PEERS':  #lista peers ativos
                peers_list = list(active_peers.keys())
                send_json(conn, {"status": "ok", "peers": peers_list})

            elif cmd == 'LIST_ROOMS': #lista salas  
                rooms_list = list(rooms.keys())
                send_json(conn, {"status": "ok", "rooms": rooms_list})

            elif cmd == 'CREATE_ROOM':  #cria salas novas
                room = msg.get('room')
                if room in rooms:
                    send_json(conn, {"status": "error", "msg": "Sala já existe"})
                else:
                    rooms[room] = set()
                    send_json(conn, {"status": "ok", "msg": f"Sala '{room}' criada"})

            elif cmd == 'JOIN_ROOM':   #entra em sala existente
                room = msg.get('room')
                if room not in rooms:
                    send_json(conn, {"status": "error", "msg": "Sala não existe"})
                elif not user:
                    send_json(conn, {"status": "error", "msg": "Faça login primeiro"})
                elif user in rooms[room]:
                    send_json(conn, {"status": "error", "msg": "Você já está na sala"})
                else:
                    rooms[room].add(user)
                    send_json(conn, {"status": "ok", "msg": f"Entrou na sala '{room}'"})

            else:
                send_json(conn, {"status": "error", "msg": "Comando desconhecido"})

    except Exception as e:   #eventuais erros
        print(f"[ERRO] {e}")

    finally:
        if user and user in active_peers:
            del active_peers[user]
            print(f"[DESCONECTADO] {user} saiu")
        conn.close()


def main():
    print(f"Tracker iniciando em {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  #scoekts
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_peer, args=(conn, addr), daemon=True).start()


if __name__ == '__main__':
    main()
