import socket

def main():
    # 循环进行10000次连接并发送数据
    for i in range(10000):
        # 创建 TCP 套接字
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 连接到本地的 6388 端口
        server_address = ('localhost', 6388)
        client_socket.connect(server_address)
        
        # 发送数据
        message = f"Message {i+1}"
        client_socket.sendall(message.encode())
        print(f"Sent: {message}")
        
        # 关闭套接字
        # client_socket.close()

if __name__ == "__main__":
    main()
