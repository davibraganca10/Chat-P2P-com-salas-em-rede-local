import socket
import threading
import json
import sys
import getpass
from queue import Queue
from crypto_utils import generate_keys, serialize_public_key, load_public_key, encrypt_message, decrypt_message


TRACKER_HOST = '127.0.0.1'
TRACKER_PORT = 12347
connections_lock = threading.Lock()
peer_connections = {}
user_public_keys = {}
room_peers = set()  # Peers que estão na mesma sala que você
current_room = None
my_username = None
private_key, public_key = generate_keys()
tracker_responses = Queue()
tracker_conn = None  # Variável global para a conexão do tracker
intentional_disconnect = False  # Flag para logout intencional

def get_tracker_response(timeout=5):
    """Obtém resposta do tracker com tratamento de erro"""
    try:
        return tracker_responses.get(block=True, timeout=timeout)
    except:
        return None

def reconnect_to_tracker(peer_port):
    """Reconecta ao tracker se a conexão foi perdida"""
    global tracker_conn
    if tracker_conn is not None:
        return tracker_conn  # Já conectado
    
    try:
        print("[INFO] Tentando reconectar ao tracker...")
        tracker_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tracker_conn.connect((TRACKER_HOST, TRACKER_PORT))
        # Inicia nova thread para escutar o tracker
        threading.Thread(target=listen_to_tracker, args=(tracker_conn,), daemon=True).start()
        print("[INFO] Reconectado ao tracker com sucesso.")
        return tracker_conn
    except Exception as e:
        print(f"[ERRO] Falha ao reconectar ao tracker: {e}")
        tracker_conn = None
        return None

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
        room_peers.clear()  # Limpa também os peers da sala
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
            room_peers.discard(peer_name)  # Remove da lista de peers da sala
            print(f"\n[INFO] Conexão com {peer_name} encerrada.")
        conn.close()
def handle_peer_conn(conn, addr):
    peer_name = None
    try:
        peer_info = recv_json(conn)
        if not peer_info: return
        peer_name = peer_info["user"]
        peer_key = load_public_key(peer_info["pubkey"])
        is_room_connection = peer_info.get("is_room_connection", False)
        remote_room = peer_info.get("room", None)
        
        # Responde com suas informações
        response_info = {
            "user": my_username, 
            "pubkey": serialize_public_key(public_key)
        }
        send_json(conn, response_info)
        
        with connections_lock:
            peer_connections[peer_name] = conn
            user_public_keys[peer_name] = peer_key
            # Só adiciona ao room_peers se for uma conexão de sala E estiverem na mesma sala
            if is_room_connection and current_room and remote_room == current_room:
                room_peers.add(peer_name)
                
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
def connect_to_peer(ip, port, is_room_connection=False):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        # Envia informação sobre o tipo de conexão
        connection_info = {
            "user": my_username, 
            "pubkey": serialize_public_key(public_key),
            "is_room_connection": is_room_connection,
            "room": current_room if is_room_connection else None
        }
        send_json(sock, connection_info)
        remote_info = recv_json(sock)
        if not remote_info: raise ConnectionError("Handshake falhou.")
        peer_name = remote_info["user"]
        peer_key = load_public_key(remote_info["pubkey"])
        with connections_lock:
            peer_connections[peer_name] = sock
            user_public_keys[peer_name] = peer_key
            # Só adiciona ao room_peers se for uma conexão de sala
            if is_room_connection:
                room_peers.add(peer_name)
        print(f"\n[INFO] Conectado a {peer_name}")
        threading.Thread(target=listen_to_peer_messages, args=(sock, peer_name), daemon=True).start()
        return peer_name
    except Exception as e:
        print(f"\n[ERRO] Falha ao conectar-se ao peer {ip}:{port}. {e}")
        return None
def listen_to_tracker(sock):
    global tracker_conn, intentional_disconnect
    while True:
        msg = recv_json(sock)
        if msg is None:
            if not intentional_disconnect:
                print("\n[ERRO] Conexão com o tracker perdida.")
            tracker_conn = None  # Marca que a conexão foi perdida
            intentional_disconnect = False  # Reset da flag
            break
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
                # Envia apenas para peers que estão na mesma sala
                peers_to_send = [(name, sock) for name, sock in peer_connections.items() if name in room_peers]
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
    global my_username, current_room, tracker_conn, intentional_disconnect
    tracker_conn = tracker  # Inicializa a variável global

    def print_help():
        print("\n" + "="*15 + " Comandos Disponíveis " + "="*15)
        print(" register        -> Criar novo usuário")
        print(" login           -> Fazer login")
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
    
    threading.Thread(target=listen_to_tracker, args=(tracker_conn,), daemon=True).start()
    print_help()

    while True:
        cmd = input("\nDigite comando: ").strip().lower()
        
        if cmd == 'help': print_help()
        elif cmd == 'exit': 
            intentional_disconnect = True  # Marca como desconexão intencional
            break
        
        if cmd == 'register':
            if not tracker_conn:
                tracker_conn = reconnect_to_tracker(peer_port)
                if not tracker_conn:
                    print("[ERRO] Não é possível se registrar sem conexão com o tracker.")
                    continue
            user = input("Usuário: ")
            pwd = getpass.getpass("Senha: ")
            send_json(tracker_conn, {"cmd": "REGISTER", "user": user, "password": pwd})
            resp = get_tracker_response()
            print(resp if resp else "[ERRO] Não foi possível obter resposta do tracker.")
            continue
        elif cmd == 'login':
            if my_username: print("[ERRO] Você já está logado."); continue
            if not tracker_conn:
                tracker_conn = reconnect_to_tracker(peer_port)
                if not tracker_conn:
                    print("[ERRO] Não é possível fazer login sem conexão com o tracker.")
                    continue
            user = input("Usuário: ")
            pwd = getpass.getpass("Senha: ")
            send_json(tracker_conn, {"cmd": "LOGIN", "user": user, "password": pwd, "port": peer_port})
            resp = get_tracker_response()
            if resp and resp.get("status") == "ok": my_username = user
            print(resp if resp else "[ERRO] Não foi possível obter resposta do tracker.")
            continue
        
        if not my_username:
            print("[ERRO] Comando inválido ou requer login. Comandos disponíveis: register, login, exit."); continue
            
        # ... (comandos list, create, join, etc. sem alterações) ...
        if cmd == 'list_peers':
            if not tracker_conn:
                tracker_conn = reconnect_to_tracker(peer_port)
                if not tracker_conn:
                    print("[ERRO] Não é possível listar peers sem conexão com o tracker.")
                    continue
            send_json(tracker_conn, {"cmd": "LIST_PEERS"})
            resp = get_tracker_response()
            if resp:
                print("Peers online:", resp.get("peers", []))
            else:
                print("[ERRO] Não foi possível obter lista de peers.")
        elif cmd == 'list_rooms':
            if not tracker_conn:
                tracker_conn = reconnect_to_tracker(peer_port)
                if not tracker_conn:
                    print("[ERRO] Não é possível listar salas sem conexão com o tracker.")
                    continue
            send_json(tracker_conn, {"cmd": "LIST_ROOMS"})
            resp = get_tracker_response()
            if resp:
                print("Salas disponíveis:")
                for room_info in resp.get("rooms", []): print(f" - {room_info}")
            else:
                print("[ERRO] Não foi possível obter lista de salas.")
            #aqui só lista com quem vc ta conectado
        elif cmd == 'list_conn':
            with connections_lock:
                if not peer_connections: 
                    print("Você não está conectado a nenhum peer.")
                else: 
                    print("Conectado a:", list(peer_connections.keys()))
                    if room_peers:
                        print(f"Peers na sala '{current_room}':", list(room_peers))
                    direct_peers = set(peer_connections.keys()) - room_peers
                    if direct_peers:
                        print("Conexões diretas (fora da sala):", list(direct_peers))
        elif cmd == 'create_room':
            if not tracker_conn:
                tracker_conn = reconnect_to_tracker(peer_port)
                if not tracker_conn:
                    print("[ERRO] Não é possível criar sala sem conexão com o tracker.")
                    continue
            room = input("Nome da sala: ")
            is_private = input("A sala será privada com senha? (s/n): ").lower() == 's'
            password = None
            if is_private: password = getpass.getpass("Digite a senha para a nova sala: ")
            disconnect_from_all_peers()
            send_json(tracker_conn, {"cmd": "CREATE_ROOM", "room": room, "password": password})
            resp = get_tracker_response()
            if resp and resp.get("status") == "ok": 
                current_room = room
                with connections_lock:
                    room_peers.clear()  # Nova sala, sem outros peers ainda
            print(resp if resp else "[ERRO] Não foi possível obter resposta do tracker.")
        elif cmd == 'join_room':
            if not tracker_conn:
                tracker_conn = reconnect_to_tracker(peer_port)
                if not tracker_conn:
                    print("[ERRO] Não é possível entrar em sala sem conexão com o tracker.")
                    continue
            room = input("Nome da sala: ")
            password = getpass.getpass("Senha (deixe em branco se for pública): ")
            disconnect_from_all_peers()
            send_json(tracker_conn, {"cmd": "JOIN_ROOM", "room": room, "password": password})
            resp = get_tracker_response()
            if resp:
                print(resp.get("msg"))
                if resp.get("status") == "ok":
                    current_room = room
                    with connections_lock:
                        room_peers.clear()  # Limpa a lista anterior
                    for member in resp.get("members", []):
                        if member["user"] != my_username:
                            connected_peer = connect_to_peer(member["ip"], member["port"], is_room_connection=True)
                            if connected_peer:
                                with connections_lock:
                                    room_peers.add(connected_peer)  # Adiciona à lista de peers da sala
                    print("\nVocê entrou na sala. Comandos disponíveis:")
                    print_help()
            else:
                print("[ERRO] Não foi possível obter resposta do tracker.")
        elif cmd == 'leave_room':
            if not current_room: print("[ERRO] Você não está em nenhuma sala."); continue
            if not tracker_conn:
                tracker_conn = reconnect_to_tracker(peer_port)
                if not tracker_conn:
                    print("[ERRO] Não é possível sair da sala sem conexão com o tracker.")
                    continue
            send_json(tracker_conn, {"cmd": "LEAVE_ROOM"})
            resp = get_tracker_response()
            if resp:
                print(resp.get("msg"))
                if resp.get("status") == "ok":
                    disconnect_from_all_peers()  # Isso já limpa room_peers também
            else:
                print("[ERRO] Não foi possível obter resposta do tracker.")

       
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
                if not tracker_conn:
                    tracker_conn = reconnect_to_tracker(peer_port)
                    if not tracker_conn:
                        print("[ERRO] Não é possível conectar sem conexão com o tracker.")
                        continue
                print(f"[INFO] Não conectado a '{target}'. Buscando informações no tracker...")
                send_json(tracker_conn, {"cmd": "GET_PEER_INFO", "target_user": target})
                resp = get_tracker_response()

                if resp and resp.get("status") == "ok":
                    peer_ip = resp.get("ip")
                    peer_port = resp.get("port")
                    print(f"[INFO] Conectando diretamente a {target} em {peer_ip}:{peer_port}...")
                    if not connect_to_peer(peer_ip, peer_port, is_room_connection=False):
                        print(f"[ERRO] Falha ao estabelecer conexão direta com {target}.")
                        continue #volta pro menu
                else:
                    error_msg = resp.get("msg", "Não foi possível obter informações do peer.") if resp else "Não foi possível obter resposta do tracker."
                    print(f"[ERRO] {error_msg}")
                    continue # tmb volta pro menu

            #modo chat (loop)
            enter_chat_loop("peer", target_peer=target)

        elif cmd == 'msg_room':

            enter_chat_loop("room")
        #logica pra kickar alguém da sala.
        elif cmd == 'kick':
            if not current_room: print("[ERRO] Você precisa estar em uma sala para expulsar alguém."); continue
            if not tracker_conn:
                tracker_conn = reconnect_to_tracker(peer_port)
                if not tracker_conn:
                    print("[ERRO] Não é possível expulsar sem conexão com o tracker.")
                    continue
            target = input("Quem você quer expulsar? (usuário): ")
            send_json(tracker_conn, {"cmd": "KICK_PEER", "room": current_room, "target_user": target})
            resp = get_tracker_response()
            print(resp if resp else "[ERRO] Não foi possível obter resposta do tracker.")
        elif cmd == 'logout':
            if tracker_conn:
                try:
                    intentional_disconnect = True  # Marca como desconexão intencional
                    send_json(tracker_conn, {"cmd": "LOGOUT"})
                    resp = get_tracker_response(timeout=2)
                    if resp and resp.get("msg"):
                        print(resp.get("msg"))
                    else:
                        print("Logout realizado.")
                except:
                    print("Logout realizado (sem conexão com tracker).")
                finally:
                    # Fecha a conexão com o tracker após logout
                    try:
                        tracker_conn.close()
                    except:
                        pass
                    tracker_conn = None
            else:
                print("Logout realizado.")
            
            disconnect_from_all_peers()
            my_username = None
            print("Você foi deslogado.")
        else:
            print("[ERRO] Comando inválido. Digite 'help' para ajuda.")


def main():
    global tracker_conn, my_username
    if len(sys.argv) < 2:
        print(f"Uso: python {sys.argv[0]} <porta_peer>"); sys.exit(1)
    peer_port = int(sys.argv[1])
    start_peer_server(peer_port)
    local_tracker_conn = None
    try:
        local_tracker_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_tracker_conn.connect((TRACKER_HOST, TRACKER_PORT))
        peer_menu(local_tracker_conn, peer_port)
    except ConnectionRefusedError:
        print("[ERRO] Não foi possível conectar ao tracker. Verifique se ele está online.")
    except Exception as e:
        print(f"[ERRO] Uma exceção inesperada ocorreu: {e}")
    finally:
        # Só tenta logout se ainda há usuário logado e conexão ativa
        if my_username and tracker_conn and not intentional_disconnect:
            try:
                send_json(tracker_conn, {"cmd": "LOGOUT"})
            except:
                pass  # Ignora erros ao tentar fazer logout na saída
        print("Encerrando cliente...")
        disconnect_from_all_peers()
        # Fecha a conexão local se ainda estiver aberta
        if local_tracker_conn:
            try:
                local_tracker_conn.close()
            except:
                pass

if __name__ == '__main__':
    main()