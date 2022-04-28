# Echo server program
import socket
import reset_timer
import os

HOST = ''                 # Symbolic name meaning all available interfaces
PORT = 6000              # Arbitrary non-privileged port
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)

rt = None

def callback():
  print("no more request exiting")
  os._exit(1)

test_num = 0
while True:
  conn, addr = s.accept()
  if test_num == 0:
    rt = reset_timer.TimerReset(30, callback)
    rt.start()
  else:
    rt.reset()
  print ('Connected by', addr)
  data_acc = b''
  while True:
    data = conn.recv(1024)
    if not data: break
    data_acc += data
    print(data)
  print("send data back")
  print(data_acc)
  conn.sendall(data_acc)
  conn.close()

