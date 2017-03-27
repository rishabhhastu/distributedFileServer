import socket
import configparser
import os
import sys 
import hashlib
import base64
from cryptography import fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
def x_value(filename):
    hash_generated = hashlib.md5()
    hash_generated.update(filename.encode())
    final_hash = hash_generated.hexdigest()
    decider_value = int(final_hash,16)%4
    return decider_value

def fetch_parts(filename, parts_stored_list_0,part_from_server, server,part_data,subfolder):
    print("IM HEREEEE")
    print(str(part_from_server) + server)
    to_get_part_1 = 'GET'+'||||'+filename+'||||'+str(parts_stored_list_0)+'||||' + str(part_from_server)+'||||'+subfolder+'||||'+'****'
    socket_dict[server].sendall(to_get_part_1.encode()) 
    try: 
        received = []
        while(1):  
            socket_dict[server].settimeout(2) 
            message_encoded = socket_dict[server].recv(BUFFER)
            if b'****' in message_encoded:
#                 print("In break")
                received.append(message_encoded)
                break
            else:
#                 print("Im else")
#                 print(message_encoded)
                received.append(message_encoded)
    #             print(message_encoded[50000:])
        received = b' '.join(received)
        message_e = received
#         message_d = message_e.decode()
#         print(message_e)
        part = int(message_e.split(b'||||')[0].decode())
        data = message_e.split(b'||||')[1]
        part_data[part] = data
        return 1
    except socket.timeout:
        print("File part missing")
        file_incomplete = 1
        return 0
def PUT(username,password,filename,socket_dict,subfolder):
    file_size = os.path.getsize(filename)
    print(file_size)
    quot = file_size//4
    rem = file_size%4
    size_piece_1_2_3 = quot
    size_piece_4 = quot+rem
    filehandler = open(filename , 'rb')
    list_parts = []
    
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
    password = str.encode(password)
    key = base64.urlsafe_b64encode(kdf.derive(password))
    cipher_suite = fernet.Fernet(key)
    for i in range(0,4):
        if i != 3 :
            data_read = filehandler.read(size_piece_1_2_3)
            cipher_text = cipher_suite.encrypt(data_read)
            list_parts.append(cipher_text)
        else:
            data_read = filehandler.read(size_piece_4)
            cipher_text = cipher_suite.encrypt(data_read)
            list_parts.append(cipher_text)
    
    list_of_pairs=[(list_parts[0],list_parts[1]),(list_parts[1],list_parts[2]),(list_parts[2],list_parts[3]),(list_parts[3],list_parts[0])]
    decider_value = x_value(filename)

    for i in range(0,decider_value):
        temp = list_of_pairs[3]
        list_of_pairs[3] = list_of_pairs[2]
        list_of_pairs[2] = list_of_pairs[1]
        list_of_pairs[1] = list_of_pairs[0]
        list_of_pairs[0] = temp
    
    subfolder = subfolder.encode()
    for i in socket_dict.keys():                                        #sending the request to put the data
        try:
            if i == "DFS1":
                to_send = b'PUT'+b'||||'+filename.encode()+b'||||'+ list_of_pairs[0][0]+b'||||'+list_of_pairs[0][1]+b'||||'+subfolder+b'||||'+b'****'
                socket_dict[i].sendall(to_send)
                no_use = socket_dict[i].recv(BUFFER)
                print(no_use.decode())
#                 print('1 ' + to_send )
            if i == "DFS2":
                to_send = b'PUT'+b'||||'+filename.encode()+b'||||'+list_of_pairs[1][0]+b'||||'+list_of_pairs[1][1]+b'||||'+subfolder+b'||||'+b'****'
                socket_dict[i].sendall(to_send)
                no_use = socket_dict[i].recv(BUFFER)
#                 print('2 ' + to_send )
            if i == "DFS3":
                to_send = b'PUT'+b'||||'+filename.encode()+b'||||'+list_of_pairs[2][0]+b'||||'+list_of_pairs[2][1]+b'||||'+subfolder+b'||||'+b'****'
                socket_dict[i].sendall(to_send)
                no_use = socket_dict[i].recv(BUFFER)
#                 print('3 ' + to_send )
            if i == "DFS4":
                to_send = b'PUT'+b'||||'+filename.encode()+b'||||'+list_of_pairs[3][0]+b'||||'+list_of_pairs[3][1]+b'||||'+subfolder+b'||||'+b'****'
                socket_dict[i].sendall(to_send)
                no_use = socket_dict[i].recv(BUFFER)
#                 print('4 ' + to_send )
        except Exception as e:
            print(e)
        
def GET(username,password,filename,socket_dict,subfolder):
    decider_value = x_value(filename)
    parts_stored_list_0 = [[0,1],[1,2],[2,3],[3,0]]                                                                 
    for i in range(0,decider_value):
        temp = parts_stored_list_0[3]
        parts_stored_list_0[3] = parts_stored_list_0[2]
        parts_stored_list_0[2] = parts_stored_list_0[1]
        parts_stored_list_0[1] = parts_stored_list_0[0]
        parts_stored_list_0[0] = temp                                                                   #calculating the oder according to the x value
        
    part_data = {}
    file_incomplete = 0
    no_file_dfs1 = 1
    no_file_dfs3 = 1
    dfs1_part_1 = 0
    dfs1_part_2 = 0
    dfs3_part_1 = 0
    dfs3_part_2 = 0
    print("IM in GET")
    count = 0
    is_file = 0
    master_servers_original = ["DFS1","DFS3"]
    master_servers = []
    for servers in master_servers_original:
        if servers in socket_dict.keys():
            master_servers.append(servers)                                                                  #checking which master servers to request
    slave_servers_original = ["DFS2","DFS4"]
    slave_servers = []
    for servers in slave_servers_original:                                                                  #checking which slave servers to request
        if servers in socket_dict.keys():
            slave_servers.append(servers)
    
    master_servers_shutdown = 0
    if len(master_servers) !=2:
        master_servers_shutdown = 1    
    print(master_servers)
    print(slave_servers)
    for servers in master_servers:
        part_recev_1 = 0
        part_recev_2 = 0 
        try:
            to_get = 'GET'+'||||'+filename+'||||'+str(parts_stored_list_0[int(servers[3])-1])+'||||'+subfolder+'||||'+'****'
            socket_dict[servers].sendall(to_get.encode())
#             socket_dict[servers].settimeout(2)
            received = []
            while(1):   
                message_encoded = socket_dict[servers].recv(BUFFER)
                if b'****' in message_encoded:
                    received.append(message_encoded)
                    break
                else:
                    received.append(message_encoded)
            received = b' '.join(received)
            message_e = received

            part = int(message_e.split(b'||||')[0].decode())
            data = message_e.split(b'||||')[1]
            if data == b'not found' or data == b'Folder Unavailable':
                print("not found part " + str(part))
            else:
                if servers == 'DFS1':
                    dfs1_part_1 = 1
                if servers == 'DFS3':
                    dfs3_part_1 = 1
                part_recev_1 = 1
                print("PART 1 FOUND")
                part_data[part] = data
            socket_dict[servers].sendall("Thanks".encode())
            received = []
            while(1):   
                message_encoded = socket_dict[servers].recv(BUFFER)
                if b'****' in message_encoded:
                    received.append(message_encoded)
                    break
                else:
                    received.append(message_encoded)
            received = b' '.join(received)
            message_e = received

            part = int(message_e.split(b'||||')[0].decode())
            data = message_e.split(b'||||')[1]
            if data == b'not found'or data == b'Folder Unavailable':
                print("not found part " + str(part))
            else:
                if servers == 'DFS1':
                    dfs1_part_2 = 1
                if servers == 'DFS3':
                    dfs3_part_2 = 1
                part_recev_2 = 1
                part_data[part] = data
            socket_dict[servers].sendall("Thanks".encode())    
            
            if part_recev_1 == 1 and part_recev_2 == 1: 
                if servers == 'DFS1':
                    no_file_dfs1 = 0
                elif servers =='DFS3':
                    no_file_dfs3 = 0
            
            if part_recev_1 ==0 and part_recev_2 ==1 and master_servers_shutdown ==0:
                print("Im in Not Part 1")
                if servers == 'DFS1':
                    part_from_server = 2
                    server = 'DFS4'
                    parts_stored = parts_stored_list_0[3]
                    flag = fetch_parts(filename , parts_stored,part_from_server, server,part_data,subfolder)
                    if flag ==1 :
                        no_file_dfs1 = 0
#                         dfs1_part_1 = 1
                elif servers == 'DFS3':
                    part_from_server = 2
                    server = 'DFS2'
                    parts_stored = parts_stored_list_0[1]
                    flag = fetch_parts(filename , parts_stored,part_from_server, server,part_data,subfolder)
                    if flag ==1 :
                        no_file_dfs3 = 0
            if part_recev_2 == 0 and part_recev_1 ==1 and master_servers_shutdown ==0:
                print("Im in Not Part 2")
                if servers == 'DFS1':
                    part_from_server = 1
                    server = 'DFS2'
                    parts_stored = parts_stored_list_0[1]
                    flag = fetch_parts(filename , parts_stored,part_from_server, server,part_data,subfolder)
                    if flag ==1 :
                        no_file_dfs1 = 0

                elif servers == 'DFS3':
                    part_from_server = 1
                    server = 'DFS4'
                    parts_stored = parts_stored_list_0[3]
                    flag = fetch_parts(filename , parts_stored,part_from_server, server,part_data,subfolder)
                    if flag ==1 :
                        no_file_dfs3 = 0

            print("Another Server")
        except socket.timeout:
            count+=1
    print(str(dfs1_part_1) + str(dfs1_part_2) + str(dfs3_part_1) + str(dfs3_part_2))
    print(str(no_file_dfs1) + str(no_file_dfs3))
    if no_file_dfs1 ==1 and no_file_dfs3 ==0:                                                               #If server 1 is down and server 3 is up
        print("Im in 10")   
        print(str(dfs3_part_1) + str(dfs3_part_2))
        if dfs1_part_1 == 0 and dfs3_part_2==1:
            part_from_server = 2
            server = 'DFS4'
            parts_stored = parts_stored_list_0[3]
            flag = fetch_parts(filename , parts_stored,part_from_server, server,part_data,subfolder)          #DFS1 - Part 1
            if flag == 0:
                file_incomplete = 1
        if dfs1_part_2 == 0 and dfs3_part_1==1:
            part_from_server = 1
            server = 'DFS2'
            parts_stored = parts_stored_list_0[1]
            flag = fetch_parts(filename , parts_stored, part_from_server, server,part_data,subfolder)         #DFS1 - Part 2 
            if flag == 0:
                file_incomplete = 1

    if no_file_dfs1 ==1 and no_file_dfs3 ==0:
           
        if dfs1_part_1 == 0 and dfs3_part_2==0:
            part_from_server = 2
            server = 'new'
            parts_stored = parts_stored_list_0[3]
            another_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_dict['new'] = another_sock
            another_sock.connect(('127.0.0.1',10004))
            auth_req = username + '||||' + password
            another_sock.sendall(auth_req.encode())
            no_use = another_sock.recv(BUFFER)
            print(no_use)
            flag = fetch_parts(filename , parts_stored,part_from_server, server,part_data,subfolder)          #DFS1 - Part 1
            if flag == 0:
                file_incomplete = 1
            
        if dfs1_part_2 == 0 and dfs3_part_1==0:
            part_from_server = 1
            server = 'new'
            parts_stored = parts_stored_list_0[1]
            another_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_dict['new'] = another_sock
            another_sock.connect(('127.0.0.1',10002))
            auth_req = username + '||||' + password
            another_sock.sendall(auth_req.encode())
            no_use = another_sock.recv(BUFFER)
            print(no_use)
            flag = fetch_parts(filename , parts_stored, part_from_server, server,part_data,subfolder)         #DFS1 - Part 2 
            if flag == 0:
                file_incomplete = 1
        
    if no_file_dfs1 ==0 and no_file_dfs3 ==1:                                                               #if server 3 is down but server 1 is up
        print("Im in 01")
        if dfs3_part_2 ==0 and dfs1_part_1 ==1:
            part_from_server = 1
            server = 'DFS4'
            parts_stored = parts_stored_list_0[3]
            flag = fetch_parts(filename , parts_stored,part_from_server, server,part_data,subfolder)          #DFS3 - Part 2
            if flag == 0:
                file_incomplete = 1
        if dfs3_part_1 == 0 and dfs1_part_2 == 1:
            part_from_server = 2
            server = 'DFS2'
            parts_stored = parts_stored_list_0[1]
            flag = fetch_parts(filename , parts_stored, part_from_server, server,part_data,subfolder)         #DFS3 - PArt 1
            if flag == 0:
                file_incomplete = 1
    if no_file_dfs1 ==0 and no_file_dfs3 ==1:           
        if dfs3_part_2 ==0 and dfs1_part_1 ==0:
            print('*')
            part_from_server = 1
            server = 'new'
            parts_stored = parts_stored_list_0[3]
            another_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_dict['new'] = another_sock
            another_sock.connect(('127.0.0.1',10004))
            auth_req = username + '||||' + password
            another_sock.sendall(auth_req.encode())
            no_use = another_sock.recv(BUFFER)
            print(no_use)
            flag = fetch_parts(filename , parts_stored,part_from_server, server,part_data,subfolder)          #DFS3 - Part 2
            if flag == 0:
                file_incomplete = 1
        if dfs3_part_1 == 0 and dfs1_part_2 == 0:
            print('[]')
            part_from_server = 2
            server = 'new'
            parts_stored = parts_stored_list_0[1]
            another_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_dict['new'] = another_sock
            another_sock.connect(('127.0.0.1',10002))
            auth_req = username + '||||' + password
            another_sock.sendall(auth_req.encode())
            no_use = another_sock.recv(BUFFER)
            print(no_use)
            flag = fetch_parts(filename , parts_stored, part_from_server, server,part_data,subfolder)         #DFS3 - PArt 1
            if flag == 0:
                file_incomplete = 1
            
    if no_file_dfs1 == 1 and no_file_dfs3 ==1 :                                                     #if neither master servers are up
        for servers in slave_servers:
            print("Im here")
            print(servers)
            to_get = 'GET'+'||||'+filename+'||||'+str(parts_stored_list_0[int(servers[3])-1]) +'||||' + str(9)+'||||'+subfolder+'||||'+'****'
            socket_dict[servers].sendall(to_get.encode())
            socket_dict[servers].settimeout(2)
            try:
                received = []
                while(1):   
                    message_encoded = socket_dict[servers].recv(BUFFER)
                    if b'****' in message_encoded:
                        received.append(message_encoded)
                        break
                    else:
                        received.append(message_encoded)
            #             print(message_encoded[50000:])
                received = b' '.join(received)
                message_e = received
#                 message_d = message_e.decode()
                part = int(message_e.split(b'||||')[0].decode())
                data = message_e.split(b'||||')[1]
                part_data[part] = data
                socket_dict[servers].sendall("Thanks".encode()) 
            except socket.timeout:
                file_incomplete = 1
            
            try:
                received = []
                while(1):   
                    message_encoded = socket_dict[servers].recv(BUFFER)
                    if b'****' in message_encoded:
                        received.append(message_encoded)
                        break
                    else:
                        received.append(message_encoded)

                received = b' '.join(received)
                message_e = received

                part = int(message_e.split(b'||||')[0].decode())
                data = message_e.split(b'||||')[1]
                part_data[part] = data
            except socket.timeout:
                file_incomplete = 1
                
    print(part_data.keys())
    if len(part_data.keys())==0:
        print("FILE NOT FOUND")
        return
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())         #For decryption
    password = str.encode(password)
    key = base64.urlsafe_b64encode(kdf.derive(password))
    cipher_suite = fernet.Fernet(key)
    
    print(count)
    if os.path.isdir(username) == 0:
        os.mkdir(username)
    if  len(part_data.keys()) == 4:
        filehandler = open(username+'\\'+filename,'wb+')
        for i in range(0,4):
            part_data[i] = cipher_suite.decrypt(part_data[i])
            filehandler.write(part_data[i])
    else:
        print("FILE INCOMPLETE") 
    
    for servers in socket_dict.keys():
        socket_dict[servers].close() 

       
def LIST(username,password,socket_dict,subfolder):
    list_of_files = {}
    list_of_pieces = []
    single_list = []
    can_be_regenerated = []
    cannot_be_reg = []
    count_for_no_files = 0
    for i in socket_dict.keys():
        to_send = 'LIST'+'||||'+username+'||||'+subfolder+'||||'+'****'
        socket_dict[i].sendall(to_send.encode())
        
        message_e = socket_dict[i].recv(BUFFER)
        message_d = message_e.decode()
        if message_d == 'No Files Present':
            count_for_no_files+=1
        else:
            socket_dict[i].sendall("PLEASE SEND".encode())
            for x in range (0,int(message_d)):
                message_e = socket_dict[i].recv(BUFFER)
                message_d = message_e.decode()
                piece = message_d.split('||||')[0]
                list_of_pieces.append(piece)
                file = message_d.split('||||')[1]
                list_of_files[file] = x
    if count_for_no_files == 4:
        print("NO FILES PRESENT")
        return
    list_of_pieces.append('x')
    list_of_pieces.sort()
    for i in range(0,len(list_of_pieces)-1):
        if list_of_pieces[i] != list_of_pieces[i+1]:
            single_list.append(list_of_pieces[i])
    count = 10
    filename_regenerated = ''
    for i in range(0,len(single_list)-1):                                                               #To avoid list index errors as we are equating with the next item
        piece_split = single_list[i].split('.')
        piece_number = int(piece_split[3])
        count = count - piece_number
        filename_regenerated = piece_split[1]+'.'+piece_split[2]
        if i != len(single_list)-2:
            piece_split_next = single_list[i+1].split('.')
            filename_regenerated_next = piece_split_next[1]+'.'+piece_split_next[2]                     #To compare with the next item in sequence
        else:
            piece_split_next = single_list[i+1].split('.')
            filename_regenerated_next = piece_split_next[1]+'.'+piece_split_next[2]
            if filename_regenerated == filename_regenerated_next:
                count = count - int(piece_split_next[3])
                if count != 0 :
                    cannot_be_reg.append(filename_regenerated)
            else:
                cannot_be_reg.append(filename_regenerated_next)
        if count == 0:
            can_be_regenerated.append(filename_regenerated)
        if filename_regenerated != filename_regenerated_next:
            if count != 0:
                cannot_be_reg.append(filename_regenerated)
            count=10
    if len(single_list) < 4:                                                    #if only one file was there in the server and the pieces are missing
        cannot_be_reg.append(filename_regenerated)
    print("FILES FOUND")   
    for files in can_be_regenerated:
        print(files)
    for files in cannot_be_reg:
        print(files + '[incomplete]')
   
if __name__ == "__main__":
    BUFFER = 65535
    salt = b'\xf7\xf7\x19\x1d\xec4f\x80\xb8\xf7\x88R\xe4a\xa6\x96'
    if len(sys.argv) == 1:
        config_file = "dfc.conf"
    elif len(sys.argv) == 2:
        config_file = sys.argv[1]
    else:
        print("Wrong number of Arguments. Please Check")
        sys.exit()
    while 1 :
        try:
        #     dict_servers = ConfigSectionMap("servers")
            user_input = input("Enter the command you want to send. Choose from the given options\n1.GET\n2.PUT\n3.LIST\n4.EXIT\n")
            config = configparser.RawConfigParser()
            if os.path.isfile(config_file):
                config.read(config_file)
            
            else:
                print("Config Details are not found")
                print("Closing Socket")
        #         "______________"
                sys.exit()
        #     user_cred = ConfigSectionMap("user_credentials")
            dict_servers = []
            dict_servers.append(config.get('servers','DFS1'))
            dict_servers.append(config.get('servers','DFS2'))
            dict_servers.append(config.get('servers','DFS3'))
            dict_servers.append(config.get('servers','DFS4'))
            username=config.get('user_credentials','username')
            password=config.get('user_credentials','password')
            socket_dict = {} 
            for i in range(0,4):
                try:
                    client=socket.socket(socket.AF_INET, socket.SOCK_STREAM)                        
                    ip = dict_servers[i].split(':')[0]
                    port=int(dict_servers[i].split(':')[1])
                    server_address = (ip,port)
                    client.connect(server_address)                                                  #Connecting Sockets with the respective servers
                    socket_dict['DFS'+str(i+1)]=client
                    print(i)
                except Exception:
                    print("Connect Exception")
            
            auth_req = username + '||||' + password
            for i in socket_dict.keys():
                socket_dict[i].sendall(auth_req.encode())
#                 no_use = socket_dict[i].recv(BUFFER)
            for i in socket_dict.keys():                                                    #USER AUTHENTICATION
                try:
                    authentication_reply_e = socket_dict[i].recv(1024)
                    authentication_reply_d = authentication_reply_e.decode()
                except Exception:
                    print("RECEV EXCEPTION")
            print('Server Reply: ' + authentication_reply_d)
            if authentication_reply_d.split()[0] == 'Invalid':
                sys.exit()
            
            user_input = user_input.split()
            if len(user_input) == 3:
                command = user_input[0].upper()
                if command not in ["GET","PUT"]:
                    print("WRONGGGG COMMAND....TO be modified!!!")
                    continue
                filename = user_input[1]
                subfolder = user_input[2]
                if '.' in subfolder:
                    print("INVALID SUBFOLDER")
                    continue
            elif len(user_input) == 2:
                command = user_input[0].upper()
                if command not in ["GET","PUT","LIST"]:
                    print("WRONGGGG COMMAND....TO be modified!!!")
                    continue
                if command == "LIST":
                    subfolder = user_input[1]
                    if '.' in subfolder:
                        print("INVALID SUBFOLDER")
                        continue
                else:
                    filename = user_input[1]
                    subfolder = "No.No"
                
            elif len(user_input) == 1:
                command = user_input[0].upper()
                if command not in ["LIST","EXIT"]:
                    print("WRONGGGG COMMAND....TO be modified!!!")
                    continue
                subfolder = "No.No"
            else:
                print("WRONGGGG COMMAND....TO be modified!!!")         
            if command == 'PUT':
                PUT(username,password,filename,socket_dict,subfolder)
            
            if command == 'GET':
                GET(username,password,filename,socket_dict,subfolder)
                
            if command == 'LIST':
                LIST(username,password,socket_dict,subfolder)
            if command == 'EXIT':
                print("Exiting the system")
                for i in socket_dict.keys():
                    to_send = 'EXIT'+'||||'+username+'||||'+subfolder+'||||'+'****'
                    socket_dict[i].sendall(to_send.encode())
                    socket_dict[i].close()
                sys.exit()
            
        except KeyboardInterrupt:
            sys.exit() 
        
        except Exception as e:
            print(e)
