import socket
import threading
import json
import sys
from crypto_utils import generate_keys, serialize_public_key, load_public_key, encrypt_message, decrypt_message

TRACKER_HOST = '127.0.0.1'
TRACKER_PORT = 12345

# Estado do Peer
peer_connections = {}
user_public_keys = {}
current_room = None
my_username = None
private_key, public_key = generate_keys()

def send_json(sock, obj):
    try:
        data = json.dumps(obj).encode()
        sock.sendall(len(data).to_bytes(4, 'big') + data)
    except (ConnectionResetError, BrokenPipeError) as e:
        print(f"[AVISO] Conexão com o servidor perdida: {e}")
    except Exception as e:
        print(f"[ERRO] Falha ao enviar JSON: {e}")

def recv_json(sock):
    length_bytes = sock.recv(4)
    if not length_bytes: return None
    length = int.from_bytes(length_bytes, 'big')
    data = b''
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet: return None
        data += packet
    return json.loads(data.decode())

def handle_peer_conn(conn, addr):
    peer_name = None
    try:
        peer_info = recv_json(conn)
        peer_name = peer_info["user"]
        peer_key = load_public_key(peer_info["pubkey"])

        send_json(conn, {"user": my_username, "pubkey": serialize_public_key(public_key)})

        peer_connections[peer_name] = conn
        user_public_keys[peer_name] = peer_key
        print(f"\n[INFO] {peer_name} conectou-se a você.")

        while True:
            length_bytes = conn.recv(4)
            if not length_bytes: break
            length = int.from_bytes(length_bytes, 'big')
            enc_msg = conn.recv(length)
            if not enc_msg: break
            
            msg = decrypt_message(private_key, enc_msg)
            
            # --- ALTERAÇÃO AQUI ---
            # Verifica se a mensagem segue o padrão de sala: "[nome_sala][usuario]: texto"
            if msg.startswith('[') and ']:' in msg:
                print(f"\n[GRUPO] {msg}")
            else:
                print(f"\n[PRIVADO] {msg}")
            # --- FIM DA ALTERAÇÃO ---

    except Exception:
        pass
    finally:
        if peer_name and peer_name in peer_connections:
            del peer_connections[peer_name]
            del user_public_keys[peer_name]
            print(f"\n[INFO] Conexão com {peer_name} encerrada.")
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

def disconnect_from_room():
    global current_room, peer_connections, user_public_keys
    if not peer_connections:
        return
    print(f"[INFO] Desconectando de todos os peers da sala '{current_room}'...")
    for sock in peer_connections.values():
        sock.close()
    peer_connections.clear()
    user_public_keys.clear()
    current_room = None

def connect_to_peer(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))

        send_json(sock, {"user": my_username, "pubkey": serialize_public_key(public_key)})

        remote_info = recv_json(sock)
        peer_name = remote_info["user"]
        peer_key = load_public_key(remote_info["pubkey"])

        peer_connections[peer_name] = sock
        user_public_keys[peer_name] = peer_key
        print(f"[INFO] Conectado a {peer_name}")

        threading.Thread(target=handle_peer_conn, args=(sock, (ip, port)), daemon=True).start()
        return peer_name
    except Exception as e:
        print(f"[ERRO] Falha ao conectar-se ao peer {ip}:{port}. {e}")
        return None

def peer_menu(tracker, peer_port):
    global my_username, current_room

    def print_help():
        print("\n" + "="*15 + " Comandos Disponíveis " + "="*15)
        print("register       -> Criar novo usuário")
        print("login          -> Fazer login")
        print("list_peers     -> Listar usuários online")
        print("list_rooms     -> Listar salas existentes")
        print("create_room    -> Criar nova sala de chat")
        print("join_room      -> Entrar em uma sala")
        print("leave_room     -> Sair da sala atual")
        print("msg            -> Enviar mensagem privada para peer conectado")
        print("msg_room       -> Enviar mensagem para todos os peers da sala")
        print("show_key       -> Mostrar sua chave pública")
        print("logout         -> Sair da conta atual")
        print("exit           -> Fechar o programa")
        print("="*52)

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
            if my_username:
                print("[ERRO] Você já está logado. Faça logout primeiro.")
                continue
            user = input("Usuário: ")
            pwd = input("Senha: ")
            send_json(tracker, {"cmd": "LOGIN", "user": user, "password": pwd, "port": peer_port})
            resp = recv_json(tracker)
            if resp and resp.get("status") == "ok":
                my_username = user
            print(resp)

        elif cmd == 'list_peers':
            send_json(tracker, {"cmd": "LIST_PEERS"})
            resp = recv_json(tracker)
            print("Peers online:", resp.get("peers", []))

        elif cmd == 'list_rooms':
            send_json(tracker, {"cmd": "LIST_ROOMS"})
            resp = recv_json(tracker)
            print("Salas disponíveis:", resp.get("rooms", []))

        elif cmd == 'create_room':
            if not my_username:
                print("[ERRO] Você precisa estar logado.")
                continue
            room = input("Nome da sala: ")
            disconnect_from_room()
            send_json(tracker, {"cmd": "CREATE_ROOM", "room": room, "user": my_username})
            resp = recv_json(tracker)
            if resp and resp.get("status") == "ok":
                current_room = room
            print(resp)

        elif cmd == 'join_room':
            if not my_username:
                print("[ERRO] Você precisa estar logado.")
                continue
            room = input("Nome da sala: ")
            disconnect_from_room()
            send_json(tracker, {"cmd": "JOIN_ROOM", "room": room, "user": my_username})
            resp = recv_json(tracker)
            print(resp.get("msg"))
            if resp.get("status") == "ok":
                current_room = room
                for member in resp.get("members", []):
                    if member["user"] != my_username:
                        connect_to_peer(member["ip"], member["port"])

        elif cmd == 'leave_room':
            if not current_room:
                print("[ERRO] Você não está em nenhuma sala.")
                continue
            send_json(tracker, {"cmd": "LEAVE_ROOM", "user": my_username})
            resp = recv_json(tracker)
            print(resp)
            if resp and resp.get("status") == "ok":
                disconnect_from_room()

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

        elif cmd == 'msg_room':
            if not current_room:
                print("[ERRO] Você precisa estar em uma sala para enviar mensagens.")
                continue
            msg_text = input("Mensagem para a sala: ")
            msg_to_send = f"[{current_room}][{my_username}]: {msg_text}"
            peers_to_remove = []
            for peer_name, peer_sock in peer_connections.items():
                try:
                    pubkey = user_public_keys[peer_name]
                    encrypted = encrypt_message(pubkey, msg_to_send)
                    peer_sock.sendall(len(encrypted).to_bytes(4, 'big') + encrypted)
                except Exception:
                    print(f"[AVISO] Não foi possível enviar mensagem para {peer_name}. Removendo da sala.")
                    peers_to_remove.append(peer_name)
            
            for peer_name in peers_to_remove:
                del peer_connections[peer_name]
                del user_public_keys[peer_name]


        elif cmd == 'show_key':
            print("\n=== SUA CHAVE PÚBLICA ===")
            print(serialize_public_key(public_key))

        elif cmd == 'logout':
            if not my_username:
                print("[ERRO] Você não está logado.")
                continue
            send_json(tracker, {"cmd": "LOGOUT"})
            resp = recv_json(tracker)
            print(resp)
            disconnect_from_room()
            my_username = None

        elif cmd == 'exit':
            print("Encerrando cliente...")
            if my_username:
                send_json(tracker, {"cmd": "LOGOUT"})
                tracker.close()
            break
        else:
            print("[ERRO] Comando inválido. Digite 'help' para ajuda.")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Uso: python {sys.argv[0]} <porta_peer>")
        sys.exit(1)

    peer_port = int(sys.argv[1])
    start_peer_server(peer_port)
    
    try:
        tracker_conn = connect_to_tracker()
        peer_menu(tracker_conn, peer_port)
    except ConnectionRefusedError:
        print("[ERRO] Não foi possível conectar ao tracker. Verifique se ele está online.")
    except Exception as e:
        print(f"[ERRO] Uma exceção inesperada ocorreu: {e}")