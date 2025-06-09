import socket
import threading
import json
import sys
from crypto_utils import generate_keys, serialize_public_key, load_public_key, encrypt_message, decrypt_message

TRACKER_HOST = '127.0.0.1'
TRACKER_PORT = 12346

peer_connections = {}
user_public_keys = {}

private_key, public_key = generate_keys()
my_username = None

def send_json(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(len(data).to_bytes(4, 'big') + data)

def recv_json(sock):
    length_bytes = sock.recv(4)
    if not length_bytes:
        return None
    length = int.from_bytes(length_bytes, 'big')
    data = b''
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            return None
        data += packet
    return json.loads(data.decode())

def handle_peer_conn(conn, addr):
    try:
        peer_info = recv_json(conn)
        peer_name = peer_info["user"]
        peer_key = load_public_key(peer_info["pubkey"])

        send_json(conn, {
            "user": my_username,
            "pubkey": serialize_public_key(public_key)
        })

        peer_connections[peer_name] = conn
        user_public_keys[peer_name] = peer_key
        print(f"[INFO] {peer_name} conectou-se a você.")

        while True:
            length = int.from_bytes(conn.recv(4), 'big')
            enc_msg = conn.recv(length)
            msg = decrypt_message(private_key, enc_msg)
            print(f"\n[PRIVADO] {msg}")
    except Exception as e:
        print(f"[ERRO] conexão com peer perdida. {e}")
        conn.close()

def start_peer_server(port):
    def server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(('0.0.0.0', port))
        srv.listen()
        print(f"[INFO] Servidor peer ouvindo na porta {port}")
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_peer_conn, args=(conn, addr), daemon=True).start()
    threading.Thread(target=server, daemon=True).start()

def connect_to_tracker():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((TRACKER_HOST, TRACKER_PORT))
    return sock

def connect_to_peer(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))

    send_json(sock, {
        "user": my_username,
        "pubkey": serialize_public_key(public_key)
    })

    remote_info = recv_json(sock)
    peer_name = remote_info["user"]
    peer_key = load_public_key(remote_info["pubkey"])

    peer_connections[peer_name] = sock
    user_public_keys[peer_name] = peer_key
    print(f"[INFO] Conectado a {peer_name}")

    threading.Thread(target=handle_peer_conn, args=(sock, ip), daemon=True).start()
    return peer_name

def peer_menu(tracker):
    global my_username

    def print_help():
        print("\n=== Comandos Disponíveis ===")
        print("register       -> Criar novo usuário")
        print("login          -> Fazer login")
        print("list_peers     -> Listar usuários online")
        print("list_rooms     -> Listar salas existentes")
        print("create_room    -> Criar nova sala de chat")
        print("join_room      -> Entrar em uma sala")
        print("connect_peer   -> Conectar-se a outro peer")
        print("msg            -> Enviar mensagem privada para peer conectado")
        print("show_key       -> Mostrar sua chave pública")
        print("logout         -> Sair da conta atual")
        print("exit           -> Fechar o programa")

    print_help()

    while True:
        cmd = input("\nDigite comando: ").strip().lower()

        if cmd == 'help':
            print_help()

        elif cmd == 'register':
            user = input("Usuário: ")
            pwd = input("Senha: ")
            send_json(tracker, {"cmd": "REGISTER", "user": user, "password": pwd})
            print(recv_json(tracker))

        elif cmd == 'login':
            user = input("Usuário: ")
            pwd = input("Senha: ")
            my_username = user
            send_json(tracker, {"cmd": "LOGIN", "user": user, "password": pwd})
            print(recv_json(tracker))

        elif cmd == 'list_peers':
            send_json(tracker, {"cmd": "LIST_PEERS"})
            resp = recv_json(tracker)
            print("Peers online:", resp.get("peers", []))

        elif cmd == 'list_rooms':
            send_json(tracker, {"cmd": "LIST_ROOMS"})
            resp = recv_json(tracker)
            print("Salas disponíveis:", resp.get("rooms", []))

        elif cmd == 'create_room':
            room = input("Nome da sala: ")
            send_json(tracker, {"cmd": "CREATE_ROOM", "room": room})
            print(recv_json(tracker))

        elif cmd == 'join_room':
            room = input("Nome da sala: ")
            send_json(tracker, {"cmd": "JOIN_ROOM", "room": room})
            print(recv_json(tracker))

        elif cmd == 'connect_peer':
            ip = input("IP do peer: ")
            port = int(input("Porta do peer: "))
            connect_to_peer(ip, port)

        elif cmd == 'msg':
            target = input("Para quem? (usuário): ")
            if target not in peer_connections:
                print("[ERRO] Você não está conectado a esse peer.")
                continue
            msg_text = input("Mensagem: ")
            pubkey = user_public_keys[target]
            encrypted = encrypt_message(pubkey, f"{my_username}: {msg_text}")
            peer_sock = peer_connections[target]
            peer_sock.sendall(len(encrypted).to_bytes(4, 'big') + encrypted)

        elif cmd == 'show_key':
            print("\n=== SUA CHAVE PÚBLICA ===")
            print(serialize_public_key(public_key))

        elif cmd == 'logout':
            send_json(tracker, {"cmd": "LOGOUT"})
            print(recv_json(tracker))
            break

        elif cmd == 'exit':
            print("Encerrando cliente...")
            break

        else:
            print("[ERRO] Comando inválido. Digite 'help' para ajuda.")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Uso: python {sys.argv[0]} <porta_peer>")
        sys.exit(1)

    peer_port = int(sys.argv[1])
    start_peer_server(peer_port)
    tracker_conn = connect_to_tracker()
    peer_menu(tracker_conn)
