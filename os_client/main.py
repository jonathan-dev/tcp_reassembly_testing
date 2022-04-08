# Echo server program
import socket

HOST = ''                 # Symbolic name meaning all available interfaces
PORT = 6000              # Arbitrary non-privileged port
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(1)

conn, addr = s.accept()
print ('Connected by', addr)
data_acc = b''
while 1:
  data = conn.recv(1024)
  if not data: break
  data_acc += data
  print(data)
print("send data back")
conn.sendall(data_acc)
conn.close()

