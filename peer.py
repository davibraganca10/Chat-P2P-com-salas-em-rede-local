import socket
import threading
import json
import sys
import getpass
from queue import Queue
from crypto_utils import generate_keys, serialize_public_key, load_public_key, encrypt_message, decrypt_message


TRACKER_HOST = '127.0.0.1'
TRACKER_PORT = 12345
connections_lock = threading.Lock()
peer_connections = {}
user_public_keys = {}
current_room = None
my_username = None
private_key, public_key = generate_keys()
tracker_responses = Queue()
def send_json(sock, obj):
    try:
        data = json.dumps(obj).encode()
        sock.sendall(len(data).to_bytes(4, 'big') + data)
    except (ConnectionResetError, BrokenPipeError): pass
    except Exception as e: print(f"\n[ERRO] Falha ao enviar JSON: {e}")
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
    except (ConnectionResetError, json.JSONDecodeError, OSError): return None
def disconnect_from_all_peers():
    global current_room
    with connections_lock:
        if not peer_connections:
            if current_room:
                print(f"\n[INFO] Você saiu da sala '{current_room}'.")
                current_room = None
            return
        print(f"\n[INFO] Desconectando de todos os peers...")
        for sock in peer_connections.values():
            try: sock.close()
            except: pass
        peer_connections.clear()
        user_public_keys.clear()
    if current_room:
        print(f"\n[INFO] Você saiu da sala '{current_room}'.")
        current_room = None
def listen_to_peer_messages(conn, peer_name):
    try:
        while True:
            key_byte_size = (private_key.key_size + 7) // 8
            enc_msg = conn.recv(key_byte_size)
            if not enc_msg: break
            msg = decrypt_message(private_key, enc_msg)
            if msg.startswith('[') and ']:' in msg: print(f"\n{msg}", end='')
            else: print(f"\n[PRIVADO] {msg}", end='')
            print("\nDigite comando: ", end=""); sys.stdout.flush()
    except Exception: pass
    finally:
        with connections_lock:
            if peer_name in peer_connections: del peer_connections[peer_name]
            if peer_name in user_public_keys: del user_public_keys[peer_name]
            print(f"\n[INFO] Conexão com {peer_name} encerrada.")
        conn.close()
def handle_peer_conn(conn, addr):
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
    except Exception: conn.close()
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
def connect_to_peer(ip, port):
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
        print(f"\n[INFO] Conectado a {peer_name}")
        threading.Thread(target=listen_to_peer_messages, args=(sock, peer_name), daemon=True).start()
        return peer_name
    except Exception as e:
        print(f"\n[ERRO] Falha ao conectar-se ao peer {ip}:{port}. {e}")
        return None
def listen_to_tracker(sock):
    while True:
        msg = recv_json(sock)
        if msg is None:
            print("\n[ERRO] Conexão com o tracker perdida."); break
        if "event" in msg:
            event = msg["event"]
            if event == "ROOM_CLOSED":
                print(f"\n[EVENTO] A sala '{msg['room']}' foi fechada pelo dono.")
                disconnect_from_all_peers()
            elif event == "YOU_WERE_KICKED":
                print(f"\n[EVENTO] Você foi expulso da sala '{msg['room']}' por '{msg['by']}'.")
                disconnect_from_all_peers()
            print("\nDigite comando: ", end=""); sys.stdout.flush()
        else:
            tracker_responses.put(msg)


 #loop de mensagem. Não precisa mais dar msg_room ou msg toda vez, só a primeira vez que entra no chat. /quit sai do chat.
def enter_chat_loop(mode, target_peer=None):

    print(f"--- Entrando no modo de chat. Digite '/quit' para sair. ---")
    
    if mode == "room":
        if not current_room:
            print("[ERRO] Você não está em uma sala.")
            return
    elif mode == "peer" and not target_peer:
        print("[ERRO] deu zebra")
        return

    while True:
        #/quit ele sai do chat
        msg_text = input()
        if msg_text == '/quit':
            print("--- Saindo do modo de chat. ---")
            break
        
        if mode == "room":
            msg_to_send = f"[{current_room}][{my_username}]: {msg_text}"
            with connections_lock:
                peers_to_send = list(peer_connections.items())
            for peer_name, peer_sock in peers_to_send:
                try:
                    pubkey = user_public_keys[peer_name]
                    encrypted = encrypt_message(pubkey, msg_to_send)
                    peer_sock.sendall(encrypted)
                except Exception as e:
                    print(f"\n[AVISO] Falha ao enviar para {peer_name}: {e}")
        
        elif mode == "peer":
            with connections_lock:
                if target_peer not in peer_connections:
                    print(f"[ERRO] Não está mais conectado a {target_peer}. Saindo do chat.")
                    break
                peer_sock = peer_connections[target_peer]
                pubkey = user_public_keys[target_peer]
            
            try:
                msg_to_send = f"{my_username}: {msg_text}"
                encrypted = encrypt_message(pubkey, msg_to_send)
                peer_sock.sendall(encrypted)
            except Exception as e:
                print(f"[ERRO] Falha ao enviar mensagem para {target_peer}: {e}")
                break


def peer_menu(tracker, peer_port):
    global my_username, current_room

    def print_help():
        print("\n" + "="*15 + " Comandos Disponíveis " + "="*15)
        print(" list_peers      -> Listar usuários online")
        print(" list_rooms      -> Listar salas existentes")
        print(" list_conn       -> Listar peers aos quais você está conectado")
        print(" create_room     -> Criar nova sala de chat (pública ou privada)")
        print(" join_room       -> Entrar em uma sala")
        print(" leave_room      -> Sair da sala atual")
        print(" msg             -> Enviar mensagem privada para um usuário (entra em modo chat)")
        print(" msg_room        -> Enviar mensagem para todos na sala (entra em modo chat)")
        print(" kick            -> (Dono) Expulsar um usuário da sua sala")
        print(" logout          -> Sair da conta atual e fechar conexões")
        print(" exit            -> Fechar o programa")
        print("="*52)
    
    threading.Thread(target=listen_to_tracker, args=(tracker,), daemon=True).start()
    print_help()

    while True:
        cmd = input("\nDigite comando: ").strip().lower()
        
        if cmd == 'help': print_help()
        elif cmd == 'exit': break
        
        if cmd == 'register':
            user = input("Usuário: ")
            pwd = getpass.getpass("Senha: ")
            send_json(tracker, {"cmd": "REGISTER", "user": user, "password": pwd})
            print(tracker_responses.get()); continue
        elif cmd == 'login':
            if my_username: print("[ERRO] Você já está logado."); continue
            user = input("Usuário: ")
            pwd = getpass.getpass("Senha: ")
            send_json(tracker, {"cmd": "LOGIN", "user": user, "password": pwd, "port": peer_port})
            resp = tracker_responses.get()
            if resp and resp.get("status") == "ok": my_username = user
            print(resp); continue
        
        if not my_username:
            print("[ERRO] Comando inválido ou requer login. Comandos disponíveis: register, login, exit."); continue
            
        # ... (comandos list, create, join, etc. sem alterações) ...
        if cmd == 'list_peers':
            send_json(tracker, {"cmd": "LIST_PEERS"})
            print("Peers online:", tracker_responses.get().get("peers", []))
        elif cmd == 'list_rooms':
            send_json(tracker, {"cmd": "LIST_ROOMS"})
            resp = tracker_responses.get()
            print("Salas disponíveis:")
            for room_info in resp.get("rooms", []): print(f" - {room_info}")
            #aqui só lista com quem vc ta conectado
        elif cmd == 'list_conn':
            with connections_lock:
                if not peer_connections: print("Você não está conectado a nenhum peer.")
                else: print("Conectado a:", list(peer_connections.keys()))
        elif cmd == 'create_room':
            room = input("Nome da sala: ")
            is_private = input("A sala será privada com senha? (s/n): ").lower() == 's'
            password = None
            if is_private: password = getpass.getpass("Digite a senha para a nova sala: ")
            disconnect_from_all_peers()
            send_json(tracker, {"cmd": "CREATE_ROOM", "room": room, "password": password})
            resp = tracker_responses.get()
            if resp and resp.get("status") == "ok": current_room = room
            print(resp)
        elif cmd == 'join_room':
            room = input("Nome da sala: ")
            password = getpass.getpass("Senha (deixe em branco se for pública): ")
            disconnect_from_all_peers()
            send_json(tracker, {"cmd": "JOIN_ROOM", "room": room, "password": password})
            resp = tracker_responses.get()
            print(resp.get("msg"))
            if resp.get("status") == "ok":
                current_room = room
                for member in resp.get("members", []):
                    if member["user"] != my_username: connect_to_peer(member["ip"], member["port"])
                print("\nVocê entrou na sala. Comandos disponíveis:")
                print_help()
        elif cmd == 'leave_room':
            if not current_room: print("[ERRO] Você não está em nenhuma sala."); continue
            send_json(tracker, {"cmd": "LEAVE_ROOM"})
            resp = tracker_responses.get()
            print(resp.get("msg"))
            if resp and resp.get("status") == "ok":
                disconnect_from_all_peers()

       
        elif cmd == 'msg':
            target = input("Para quem? (usuário): ")
            if target == my_username:
                print("[ERRO] Você não pode enviar uma mensagem para si mesmo.")
                continue

             #verifica se já existe uma conexão
            with connections_lock:
                is_connected = target in peer_connections
            
            # se não, conecta
            if not is_connected:
                print(f"[INFO] Não conectado a '{target}'. Buscando informações no tracker...")
                send_json(tracker, {"cmd": "GET_PEER_INFO", "target_user": target})
                resp = tracker_responses.get()

                if resp and resp.get("status") == "ok":
                    peer_ip = resp.get("ip")
                    peer_port = resp.get("port")
                    print(f"[INFO] Conectando diretamente a {target} em {peer_ip}:{peer_port}...")
                    if not connect_to_peer(peer_ip, peer_port):
                        print(f"[ERRO] Falha ao estabelecer conexão direta com {target}.")
                        continue #volta pro menu
                else:
                    error_msg = resp.get("msg", "Não foi possível obter informações do peer.")
                    print(f"[ERRO] {error_msg}")
                    continue # tmb volta pro menu

            #modo chat (loop)
            enter_chat_loop("peer", target_peer=target)

        elif cmd == 'msg_room':

            enter_chat_loop("room")
        #logica pra kickar alguém da sala.
        elif cmd == 'kick':
            if not current_room: print("[ERRO] Você precisa estar em uma sala para expulsar alguém."); continue
            target = input("Quem você quer expulsar? (usuário): ")
            send_json(tracker, {"cmd": "KICK_PEER", "room": current_room, "target_user": target})
            print(tracker_responses.get())
        elif cmd == 'logout':
            send_json(tracker, {"cmd": "LOGOUT"})
            print(tracker_responses.get().get("msg"))
            disconnect_from_all_peers()
            my_username = None
            print("Você foi deslogado.")
        else:
            print("[ERRO] Comando inválido. Digite 'help' para ajuda.")


def main():
    if len(sys.argv) < 2:
        print(f"Uso: python {sys.argv[0]} <porta_peer>"); sys.exit(1)
    peer_port = int(sys.argv[1])
    start_peer_server(peer_port)
    tracker_conn = None
    try:
        tracker_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tracker_conn.connect((TRACKER_HOST, TRACKER_PORT))
        peer_menu(tracker_conn, peer_port)
    except ConnectionRefusedError:
        print("[ERRO] Não foi possível conectar ao tracker. Verifique se ele está online.")
    except Exception as e:
        print(f"[ERRO] Uma exceção inesperada ocorreu: {e}")
    finally:
        if my_username and tracker_conn:
             send_json(tracker_conn, {"cmd": "LOGOUT"})
        print("Encerrando cliente...")
        disconnect_from_all_peers()
        if tracker_conn: tracker_conn.close()

if __name__ == '__main__':
    main()