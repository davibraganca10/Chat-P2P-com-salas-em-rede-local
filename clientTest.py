import socket
import json

HOST = '127.0.0.1'
PORT = 12345

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

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"Conectado ao tracker em {HOST}:{PORT}")

        while True:
            cmd_input = input("Digite comando (REGISTER, LOGIN, LOGOUT, LIST_PEERS, LIST_ROOMS, CREATE_ROOM, JOIN_ROOM, QUIT): ").strip().upper()

            if cmd_input == 'QUIT':
                print("Saindo...")
                break

            if cmd_input == 'REGISTER':
                user = input("Novo usuário: ").strip()
                password = input("Senha: ").strip()
                send_json(s, {"cmd": "REGISTER", "user": user, "password": password})

            elif cmd_input == 'LOGIN':
                user = input("Usuário: ").strip()
                password = input("Senha: ").strip()
                send_json(s, {"cmd": "LOGIN", "user": user, "password": password})

            elif cmd_input == 'LOGOUT':
                send_json(s, {"cmd": "LOGOUT"})

            elif cmd_input == 'LIST_PEERS':
                send_json(s, {"cmd": "LIST_PEERS"})

            elif cmd_input == 'LIST_ROOMS':
                send_json(s, {"cmd": "LIST_ROOMS"})

            elif cmd_input == 'CREATE_ROOM':
                room = input("Nome da sala: ").strip()
                send_json(s, {"cmd": "CREATE_ROOM", "room": room})

            elif cmd_input == 'JOIN_ROOM':
                room = input("Nome da sala: ").strip()
                send_json(s, {"cmd": "JOIN_ROOM", "room": room})

            else:
                print("Comando inválido.")
                continue

            resposta = recv_json(s)
            if resposta is None:
                print("Conexão fechada pelo servidor.")
                break
            print("Resposta:", resposta)

if __name__ == "__main__":
    main()
