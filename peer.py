import socket
import threading
import json
import sys
from crypto_utils import generate_keys, serialize_public_key, load_public_key, encrypt_message, decrypt_message

TRACKER_HOST = '127.0.0.1'
TRACKER_PORT = 12345

# Lock para proteger o acesso aos dicionários compartilhados
connections_lock = threading.Lock()

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
    except (ConnectionResetError, BrokenPipeError):
        # A conexão foi perdida, não há muito o que fazer.
        pass
    except Exception as e:
        print(f"[ERRO] Falha ao enviar JSON: {e}")

def recv_json(sock):
    try:
        length_bytes = sock.recv(4)
        if not length_bytes: return None
        length = int.from_bytes(length_bytes, 'big')
        data = b''
        while len(data) < length:
            packet = sock.recv(length - len(data))
            if not packet: return None
            data += packet
        return json.loads(data.decode())
    except (ConnectionResetError, json.JSONDecodeError):
        return None

def listen_to_peer_messages(conn, peer_name):
    """Loop principal para ouvir mensagens de um peer já conectado."""
    try:
        while True:
            length_bytes = conn.recv(4)
            if not length_bytes: break
            length = int.from_bytes(length_bytes, 'big')
            enc_msg = conn.recv(length)
            if not enc_msg: break
            
            msg = decrypt_message(private_key, enc_msg)
            
            if msg.startswith('[') and ']:' in msg:
                print(f"\n[GRUPO] {msg}")
            else:
                print(f"\n[PRIVADO] {msg}")
    except Exception:
        # Qualquer erro aqui (descriptografia, conexão) encerra a thread.
        pass
    finally:
        with connections_lock:
            if peer_name in peer_connections:
                del peer_connections[peer_name]
            if peer_name in user_public_keys:
                del user_public_keys[peer_name]
            print(f"\n[INFO] Conexão com {peer_name} encerrada.")
        conn.close()

def handle_peer_conn(conn, addr):
    """Lida com uma conexão P2P de ENTRADA, realizando o handshake."""
    peer_name = None
    try:
        peer_info = recv_json(conn)
        if not peer_info: return
        peer_name = peer_info["user"]
        peer_key = load_public_key(peer_info["pubkey"])

        send_json(conn, {"user": my_username, "pubkey": serialize_public_key(public_key)})

        with connections_lock:
            peer_connections[peer_name] = conn
            user_public_keys[peer_name] = peer_key
        print(f"\n[INFO] {peer_name} conectou-se a você.")

        listen_to_peer_messages(conn, peer_name)

    except Exception:
        conn.close()

def start_peer_server(port):
    """Inicia o servidor em uma thread para escutar por conexões de outros peers."""
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
    global current_room
    with connections_lock:
        if not peer_connections:
            return
        print(f"[INFO] Desconectando de todos os peers da sala '{current_room}'...")
        for sock in peer_connections.values():
            sock.close()
        peer_connections.clear()
        user_public_keys.clear()
    current_room = None

def connect_to_peer(ip, port):
    """Inicia uma conexão P2P de SAÍDA, realizando o handshake."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))

        send_json(sock, {"user": my_username, "pubkey": serialize_public_key(public_key)})
        remote_info = recv_json(sock)
        if not remote_info: raise ConnectionError("Handshake falhou.")

        peer_name = remote_info["user"]
        peer_key = load_public_key(remote_info["pubkey"])

        with connections_lock:
            peer_connections[peer_name] = sock
            user_public_keys[peer_name] = peer_key
        print(f"[INFO] Conectado a {peer_name}")

        threading.Thread(target=listen_to_peer_messages, args=(sock, peer_name), daemon=True).start()
        return peer_name
    except Exception as e:
        print(f"[ERRO] Falha ao conectar-se ao peer {ip}:{port}. {e}")
        return None

def peer_menu(tracker, peer_port):
    global my_username, current_room

    def print_help():
        print("\n" + "="*15 + " Comandos Disponíveis " + "="*15)
        print("register      -> Criar novo usuário")
        print("login         -> Fazer login")
        print("list_peers    -> Listar usuários online")
        print("list_rooms    -> Listar salas existentes")
        print("create_room   -> Criar nova sala de chat")
        print("join_room     -> Entrar em uma sala")
        print("leave_room    -> Sair da sala atual")
        print("msg           -> Enviar mensagem privada para um usuário")
        print("msg_room      -> Enviar mensagem para todos na sala")
        print("show_key      -> Mostrar sua chave pública")
        print("logout        -> Sair da conta atual")
        print("exit          -> Fechar o programa")
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
            if my_username: print("[ERRO] Você já está logado. Faça logout primeiro."); continue
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
            if not my_username: print("[ERRO] Você precisa estar logado."); continue
            room = input("Nome da sala: ")
            disconnect_from_room()
            send_json(tracker, {"cmd": "CREATE_ROOM", "room": room, "user": my_username})
            resp = recv_json(tracker)
            if resp and resp.get("status") == "ok":
                current_room = room
            print(resp)

        elif cmd == 'join_room':
            if not my_username: print("[ERRO] Você precisa estar logado."); continue
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
            if not current_room: print("[ERRO] Você não está em nenhuma sala."); continue
            send_json(tracker, {"cmd": "LEAVE_ROOM", "user": my_username})
            resp = recv_json(tracker)
            print(resp)
            if resp and resp.get("status") == "ok":
                disconnect_from_room()

        elif cmd == 'msg':
            if not my_username: print("[ERRO] Você precisa estar logado."); continue
            target = input("Para quem? (usuário): ")
            if target == my_username: print("[ERRO] Você não pode enviar uma mensagem para si mesmo."); continue

            with connections_lock:
                is_connected = target in peer_connections

            if not is_connected:
                print(f"[INFO] Não conectado a '{target}'. Tentando obter informações do tracker...")
                send_json(tracker, {"cmd": "GET_PEER_INFO", "target_user": target})
                resp = recv_json(tracker)
                if resp and resp.get("status") == "ok":
                    peer_ip = resp.get("ip")
                    peer_port = resp.get("port")
                    print(f"[INFO] Conectando diretamente a {target} em {peer_ip}:{peer_port}...")
                    if not connect_to_peer(peer_ip, peer_port):
                        print(f"[ERRO] Falha ao estabelecer conexão direta com {target}.")
                        continue
                else:
                    error_msg = resp.get("msg", "Não foi possível obter informações do peer.")
                    print(f"[ERRO] {error_msg}")
                    continue
            
            msg_text = input("Mensagem: ")
            
            with connections_lock:
                if target not in peer_connections:
                    print(f"[ERRO] Falha crítica ao conectar com {target}. Tente novamente.")
                    continue
                pubkey = user_public_keys[target]
                peer_sock = peer_connections[target]
            
            encrypted = encrypt_message(pubkey, f"{my_username}: {msg_text}")
            try:
                peer_sock.sendall(len(encrypted).to_bytes(4, 'big') + encrypted)
            except (ConnectionResetError, BrokenPipeError):
                print(f"[AVISO] A conexão com {target} foi perdida. Removendo peer.")
                with connections_lock:
                    if target in peer_connections:
                        del peer_connections[target]
                    if target in user_public_keys:
                        del user_public_keys[target]

        elif cmd == 'msg_room':
            if not current_room: print("[ERRO] Você precisa estar em uma sala para enviar mensagens."); continue
            msg_text = input("Mensagem para a sala: ")
            msg_to_send = f"[{current_room}][{my_username}]: {msg_text}"
            
            peers_to_remove = []
            
            with connections_lock:
                peers_to_send = list(peer_connections.items())

            for peer_name, peer_sock in peers_to_send:
                try:
                    with connections_lock:
                        if peer_name not in user_public_keys:
                            continue
                        pubkey = user_public_keys[peer_name]

                    encrypted = encrypt_message(pubkey, msg_to_send)
                    peer_sock.sendall(len(encrypted).to_bytes(4, 'big') + encrypted)
                except Exception as e:
                    print(f"\n[AVISO] Não foi possível enviar mensagem para {peer_name}. Removendo. Erro: {e}", file=sys.stderr)
                    peers_to_remove.append(peer_name)
            
            if peers_to_remove:
                with connections_lock:
                    for peer_name in peers_to_remove:
                        if peer_name in peer_connections: del peer_connections[peer_name]
                        if peer_name in user_public_keys: del user_public_keys[peer_name]

        elif cmd == 'show_key':
            print("\n=== SUA CHAVE PÚBLICA ===")
            print(serialize_public_key(public_key))

        elif cmd == 'logout':
            if not my_username: print("[ERRO] Você não está logado."); continue
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
