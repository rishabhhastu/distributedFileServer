import socket
import hashlib
import configparser
import os
import sys
import time
from threading import Thread

def user_auth(username , password , conf_username , conf_passwords,user_auth_dict):
    if username not in conf_username:
        return 0
    elif password not in conf_passwords:
        return 0
    elif user_auth_dict[username] != password:
        return 0
    else:
        return 1

def filewrite(part_1,part_2,folder,filename,username,file_part_1,file_part_2,subfolder):
    if subfolder == "No.No":
        if os.path.isdir(folder) == 0:
            os.mkdir(folder)
        if os.path.isdir(folder+'\\'+username) ==0:
            os.mkdir(folder+'\\'+username) 
        print(type(file_part_1))
    #     file_part_1 = str.encode(file_part_1)
    #     file_part_2 = str.encode(file_part_2)
        print(type(file_part_1))
        filehanlder = open(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_1+1) , 'wb')
        filehanlder.write(file_part_1)
        filehanlder = open(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_2+1) , 'wb')
        filehanlder.write(file_part_2)
        filehanlder.close()
    else:
        if os.path.isdir(folder) == 0:
            os.mkdir(folder)
        if os.path.isdir(folder+'\\'+username) ==0:
            os.mkdir(folder+'\\'+username) 
        if os.path.isdir(folder+'\\'+username+'\\'+subfolder) == 0:
            os.mkdir(folder+'\\'+username+'\\'+subfolder)
        filehanlder = open(folder+'\\'+username+'\\'+subfolder+'\\'+'.'+filename+'.'+str(part_1+1) , 'wb')
        filehanlder.write(file_part_1)
        filehanlder = open(folder+'\\'+username+'\\'+subfolder+'\\'+'.'+filename+'.'+str(part_2+1) , 'wb')
        filehanlder.write(file_part_2)
        filehanlder.close()

def x_value(filename):
    hash_generated = hashlib.md5()
    hash_generated.update(filename.encode())
    final_hash = hash_generated.hexdigest()
    decider_value = int(final_hash,16)%4
    return decider_value    

def PUT(client_to_send_list,folder,username):
    filename = client_to_send_list[1].decode()
    print(filename)
    decider_value = x_value(filename)
    subfolder = client_to_send_list[4].decode()
    print(str(decider_value) + '****')
    if decider_value == 0:
        f_save_1 = 0
        f_save_2 = 1
    elif decider_value == 1:
        f_save_1 = 3
        f_save_2 = 0
    elif decider_value == 2:
        f_save_1 = 2
        f_save_2 = 3
    elif decider_value == 3:
        f_save_1 = 1
        f_save_2 = 2
    file_part_1 = client_to_send_list[2]
    file_part_2 = client_to_send_list[3]
    if folder == 'DFS1':
        to_save_1 = f_save_1
        to_save_2 = f_save_2
        filewrite(to_save_1,to_save_2,folder,filename,username,file_part_1,file_part_2,subfolder)
    elif folder == 'DFS2':
        to_save_1 = (f_save_1+1)%4
        to_save_2 = (f_save_2+1)%4
        filewrite(to_save_1,to_save_2,folder,filename,username,file_part_1,file_part_2,subfolder)
    elif folder == 'DFS3':
        to_save_1 = (f_save_1+2)%4
        to_save_2 = (f_save_2+2)%4
        filewrite(to_save_1,to_save_2,folder,filename,username,file_part_1,file_part_2,subfolder)
    elif folder == 'DFS4' :
        to_save_1 = (f_save_1+3)%4
        to_save_2 = (f_save_2+3)%4
        filewrite(to_save_1,to_save_2,folder,filename,username,file_part_1,file_part_2,subfolder)
        
def GET(client_to_send_list,folder,username):
    dir_contents = []

    filename = client_to_send_list[1].decode()
    dir_contents_all = os.listdir(folder+'\\'+username)
    for files in dir_contents_all:
        file_components = files.split('.')
        if len(file_components) == 1:
            continue
        else:
            dir_contents.append(files)
    present = 0
    for files in dir_contents:
        file_components = files.split('.')
        file_searched = file_components[1] + '.'+file_components[2]
        if file_searched == filename:
            present = 1
    total_parts = client_to_send_list[2].decode()
    print(total_parts)
    part_1 = int(total_parts[1])
    part_2 = int(total_parts[4])
    
    if folder == 'DFS1' or folder == 'DFS3':
        subfolder = client_to_send_list[3].decode()
        print("SUBFOLDER " + subfolder)
        print("Im in above loop")
        if subfolder == "No":
            if os.path.isfile(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_1+1)):
                filehandler = open(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_1+1),'rb')
                to_send = str(part_1).encode()+b'||||'+filehandler.read()+b'||||'+b'end_of_file 1'+b'||||'+b'****'
                client.sendall(to_send)
                no_use = client.recv(BUFFER)
                filehandler.close()
                print("Send 1st part " + str(part_1+1))
            else:
                print(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_1+1))
                to_send = str(part_1).encode()+b'||||'+b'not found'+b'||||'+b'****'
                client.sendall(to_send)
        
            if os.path.isfile(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_2+1)):
                filehandler = open(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_2+1),'rb')
                to_send = str(part_2).encode()+b'||||'+filehandler.read()+b'||||'+b'end_of_file 2'+b'||||'+b'****'
                client.sendall(to_send)
                no_use = client.recv(BUFFER)
                filehandler.close()
                print("send 2nd part " + str(part_2+1))
            else:
                print(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_2+1))
                to_send = str(part_2).encode()+b'||||'+b"not found"+b'||||'+b'****'
                client.sendall(to_send)
        
        else:
            if os.path.isfile(folder+'\\'+username+'\\'+subfolder+'\\'+'.'+filename+'.'+str(part_1+1)):
                filehandler = open(folder+'\\'+username+'\\'+subfolder+'\\'+'.'+filename+'.'+str(part_1+1),'rb')
                to_send = str(part_1).encode()+b'||||'+filehandler.read()+b'||||'+b'end_of_file 1'+b'||||'+b'****'
                client.sendall(to_send)
                no_use = client.recv(BUFFER)
                filehandler.close()
                print("Send 1st part " + str(part_1+1))
            else:
                print(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_1+1))
                to_send = str(part_1).encode()+b'||||'+b'Folder Unavailable'+b'||||'+b'****'
                client.sendall(to_send)
        
            if os.path.isfile(folder+'\\'+username+'\\'+subfolder+'\\'+'.'+filename+'.'+str(part_2+1)):
                filehandler = open(folder+'\\'+username+'\\'+subfolder+'\\'+'.'+filename+'.'+str(part_2+1),'rb')
                to_send = str(part_2).encode()+b'||||'+filehandler.read()+b'||||'+b'end_of_file 2'+b'||||'+b'****'
                client.sendall(to_send)
                no_use = client.recv(BUFFER)
                filehandler.close()
                print("send 2nd part " + str(part_2+1))
            else:
                print(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_2+1))
                to_send = str(part_2).encode()+b'||||'+b"Folder Unavailable"+b'||||'+b'****'
                client.sendall(to_send)
    
    if folder == 'DFS2' or folder == 'DFS4':
        subfolder = client_to_send_list[4].decode()
        print("SUBFOLDER " + subfolder)
        print("Im in below loop")
        part = int(client_to_send_list[3])
        
        if subfolder == "No.No":
            if part == 9 :
                print("Im in 9")
                if os.path.isfile(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_1+1)):
                    filehandler = open(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_1+1),'rb')
                    to_send = str(part_1).encode()+b'||||'+filehandler.read()+b'||||'+b'****'
                    client.sendall(to_send)
                    no_use = client.recv(BUFFER)
                    filehandler.close()
                    print("Send 1st part " + str(part_1+1))
                
                if os.path.isfile(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_2+1)):
                    filehandler = open(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_2+1),'rb')
                    to_send = str(part_2).encode()+b'||||'+filehandler.read()+b'||||'+b'****'
                    client.sendall(to_send)
                    no_use = client.recv(BUFFER)
                    filehandler.close()
                    print("send 2nd part " + str(part_2+1))

            if part == 1:
                if os.path.isfile(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_1+1)):
                    filehandler = open(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_1+1),'rb')
                    to_send = str(part_1).encode()+b'||||'+filehandler.read()+b'||||'+b'****'
                    client.sendall(to_send)
                    print("Sent Part " + str(part_1 + 1))
                else:
                    print(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_1+1))
            
            elif part == 2:
                if os.path.isfile(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_2+1)):
                    filehandler = open(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_2+1),'rb')
                    to_send = str(part_2).encode()+b'||||'+filehandler.read()+b'||||'+b'****'
                    client.sendall(to_send)
                    print("Sent part " + str(part_2+1))
                else:
                    print(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_2+1))
        
        else:
            if part == 9 :
                print("Im in 9")
                if os.path.isfile(folder+'\\'+username+'\\'+subfolder+'\\'+'.'+filename+'.'+str(part_1+1)):
                    filehandler = open(folder+'\\'+username+'\\'+subfolder+'\\'+'.'+filename+'.'+str(part_1+1),'rb')
                    to_send = str(part_1).encode()+b'||||'+filehandler.read()+b'||||'+b'****'
                    client.sendall(to_send)
                    no_use = client.recv(BUFFER)
                    filehandler.close()
                    print("Send 1st part " + str(part_1+1))
                else:
                    print("FOLDER UNAVAILABLE")
                    
                if os.path.isfile(folder+'\\'+username+'\\'+subfolder+'\\'+'.'+filename+'.'+str(part_2+1)):
                    filehandler = open(folder+'\\'+username+'\\'+subfolder+'\\'+'.'+filename+'.'+str(part_2+1),'rb')
                    to_send = str(part_2).encode()+b'||||'+filehandler.read()+b'||||'+b'****'
                    client.sendall(to_send)
                    no_use = client.recv(BUFFER)
                    filehandler.close()
                    print("send 2nd part " + str(part_2+1))
                else:
                    print("FOLDER UNAVAILABLE")
            if part == 1:
                if os.path.isfile(folder+'\\'+username+'\\'+subfolder+'\\'+'.'+filename+'.'+str(part_1+1)):
                    filehandler = open(folder+'\\'+username+'\\'+subfolder+'\\'+'.'+filename+'.'+str(part_1+1),'rb')
                    to_send = str(part_1).encode()+b'||||'+filehandler.read()+b'||||'+b'****'
                    client.sendall(to_send)
                    print("Sent Part " + str(part_1 + 1))
                else:
                    print(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_1+1))
                    print("FOLDER UNAVAILABLE")        
            elif part == 2:
                if os.path.isfile(folder+'\\'+username+'\\'+subfolder+'\\'+'.'+filename+'.'+str(part_2+1)):
                    filehandler = open(folder+'\\'+username+'\\'+subfolder+'\\'+'.'+filename+'.'+str(part_2+1),'rb')
                    to_send = str(part_2).encode()+b'||||'+filehandler.read()+b'||||'+b'****'
                    client.sendall(to_send)
                    print("Sent part " + str(part_2+1))
                else:
                    print(folder+'\\'+username+'\\'+'.'+filename+'.'+str(part_2+1))
                    print("FOLDER UNAVAILABLE")

def LIST(client_to_send_list,folder,username):
    subfolder = client_to_send_list[2].decode()
    files_to_send = {}
    no_of_files= 1
    count = 0
    if subfolder == "No.No":
        if os.path.isdir(folder+'\\'+username)==0:
            no_of_files = 0
        
        else:
            files_in_folder = []
            files_in_folder_all = os.listdir(folder+'\\'+username)
#             dir_contents_all = os.listdir(folder+'\\'+username)
            for files in files_in_folder_all:
                file_components = files.split('.')
                if len(file_components) == 1:
                    continue
                else:
                    files_in_folder.append(files)
            if len(files_in_folder) == 0:
                no_of_files = 0
            else:
                for files in files_in_folder:
                    count = 1
                    splitted_names = files.split('.')
                    reconstructed_name = splitted_names[1]+'.'+splitted_names[2]
                    files_to_send[files] = reconstructed_name
    else:
        if os.path.isdir(folder+'\\'+username+'\\'+subfolder)==0:
            no_of_files = 0
        
        else:
            files_in_folder = []
            files_in_folder_all = os.listdir(folder+'\\'+username+'\\'+subfolder)
#             dir_contents_all = os.listdir(folder+'\\'+username)
            for files in files_in_folder_all:
                file_components = files.split('.')
                if len(file_components) == 1:
                    continue
                else:
                    files_in_folder.append(files)
            if len(files_in_folder) == 0:
                no_of_files = 0
            else:
                for files in files_in_folder:
                    count = 1
                    splitted_names = files.split('.')
                    reconstructed_name = splitted_names[1]+'.'+splitted_names[2]
                    files_to_send[files] = reconstructed_name
    list_of_files = files_to_send.keys()
    len_of_list = len(list_of_files)
    if no_of_files == 1:
        client.sendall(str(len_of_list).encode())
        message_d = client.recv(BUFFER)
        for key,value in files_to_send.items():
            print(key + ' ' + value)
            to_send = key + '||||' + value
            client.sendall(to_send.encode())
    else:
        client.sendall("No Files Present".encode())
        
def new_connection(client,folder):  
    auth_req_enc = client.recv(BUFFER)
#     client.sendall("Thanks".encode()) 
    auth_req_dec = auth_req_enc.decode()
    print(auth_req_dec)
    user_cred = auth_req_dec.split('||||')
    username = user_cred[0]
    password = user_cred[1]
    
    config = configparser.RawConfigParser()
    if os.path.isfile('dfs.conf'):
        config.read('dfs.conf')
    conf_username = config.options('user_credentials')
#     print(conf_username)
    conf_passwords = []
    for option in conf_username:
        conf_passwords.append(config.get('user_credentials', option))

    user_auth_dict = {}
    count = 0 
    for line in conf_username:
        user_auth_dict[line] = conf_passwords[count]
        count += 1

    flag = user_auth(username, password, conf_username, conf_passwords , user_auth_dict)
    print(flag)
    if flag != 1:
        client.sendall("Invalid Username/Password. Please try again".encode())
        return
    else:
        client.sendall("Valid Username {}".format(username).encode())
    
    if os.path.isdir(folder) == 0:
        os.mkdir(folder)
    if os.path.isdir(folder + '\\' + username) == 0:
        os.mkdir(folder + '\\' + username)   
    received = []
    while(1):   
        message_encoded = client.recv(BUFFER)
        if message_encoded == b'':
            return
        if b'****' in message_encoded:
            received.append(message_encoded)
            break
        else:
            received.append(message_encoded)

    received = b' '.join(received)
    message_decoded = received
    client_to_send_list = message_decoded.split(b'||||')
    command = client_to_send_list[0].decode()
    print(str(len(client_to_send_list)) + 'length of list')
    print(command)
    
    if command == 'PUT':
        client.sendall('Thnaks'.encode())
        PUT(client_to_send_list,folder,username)
        
    if command == 'GET':
        GET(client_to_send_list,folder,username)
    
    if command == 'LIST':
        LIST(client_to_send_list,folder,username)
    
    if command == 'EXIT':
        print("EXITING SERVER")
        print("Closing CLient")
        client.close()
        server_sock.close()
        os._exit(1)           
if __name__ == "__main__":
    if len(sys.argv)!=3:
        print("Please Look the number of arguments")
        sys.exit()
    server_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    folder = sys.argv[1]
    if folder not in ["DFS1","DFS2","DFS3","DFS4"]:
        print("INVALID FOLDER")
        sys.exit()
    port = int(sys.argv[2])
    if port < 1024  or port > 65536:                                             #Checking whether the port is below 5000 
        print("Choose a port number between 1024 and 65535")
        sys.exit()
    hostname = ''
    address = (hostname,port)
    server_sock.bind(address)
    server_sock.listen()
    BUFFER=65535
    print("SERVER STARTED")
    while 1:
        try:
            client , client_address = server_sock.accept()
            print("NEW ACCEPT " + str(client_address))
            Thread(target=new_connection, args = (client,folder,)).start()
            
        except KeyboardInterrupt:
            client.close()
            server_sock.close()
            os._exit(1)
        except Exception as e :
            print(e)