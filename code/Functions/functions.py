import getpass
import os
import sys
import Crypto.Hash as Hash
import base64

from Classdefinition import classdef

VALID_MODES = ["CBC", "CTR", "ECB"]

directory = os.path.join(os.getcwd(), "..")
data_directory = os.path.join(directory, "data")
code_directory = os.path.join(directory, "code")


def get_absolute_directory(filename, target_directory):
    global absolute_directory
    absolute_directory = os.path.join(target_directory, filename)


def is_non_zero_file(filename, target_directory):
    get_absolute_directory(filename, target_directory)
    if os.path.isfile(absolute_directory) and os.path.getsize(absolute_directory) > 0:
        return True
    else:
        return False
        
def hashed(data_value, salt_value):
    hasher = Hash.SHA256.new()
    hasher.update(salt_value + ":" + data_value)
    data_value = base64.b64encode(hasher.digest())
    return data_value

##################################################################
# File-read Function
##################################################################
def fileread(filename, target_directory):
    
    if is_non_zero_file(filename, target_directory):
        
        global data_dict
        data_dict = {}
        os.chdir(target_directory)
        myfile = open(filename, "r")
        
        for line in myfile:
            line = line.split(" ")
            line[5] = line[5].strip("\n")
            indi_record = classdef.record(line[0], line[1], line[2], line[3], line[4], line[5])
            data_dict[line[0] + line[1]] = indi_record
        
        myfile.close()
        os.chdir(code_directory)
        return data_dict
    
    else:
        return False


##################################################################
# This function adds data to the file of an authenticated user
##################################################################
def add_data():
    print "\n\n                   Add Records for %s\n" % master_username
    service = raw_input("Enter the service name: ")
    username = raw_input("Enter the username for the above service: ")
    username = username.lower()
    password = getpass.getpass(prompt = "Enter the password for the above username: ")
    c_password = getpass.getpass(prompt = "Confirm the above passord: ")
    if password != c_password:
        print "The values of the fields in Password and Confirm password do not match. PLEASE TRY AGAIN"
        add_data()
    mode = raw_input("Enter the mode to encrypt the new entry (ECB, CBC,or CTR): ")
    mode = mode.upper()
    if mode not in VALID_MODES:
        print "%s is not among the valid modes. Only ECB, CBC, CTR are valid. Please try again" % mode
        add_data()
    
    print "\nVerify the new entry:\nservice = %s" % service
    print "username = %s" % username
    print "mode = %s" % mode
    v = raw_input("\nEnter 1: Verify & Enter the above entry OR 2: Edit the entry OR 3: Home Screen OR (Any Other key): Log Out :- ")

    if v == "1":
        if fileread(master_username + "ECB", data_directory):
            for key in data_dict:
                stored_record_internal = data_dict[key]
                stored_record_internal.decrypt(master_password)
                if stored_record_internal.service == service and stored_record_internal.username == username:
                    print "\nYou have already added an entry for the given username with the given service"
                    print "                         Record not added, PLEASE TRY AGAIN\n"
                    add_data()
                
        if fileread(master_username + "CBC", data_directory):
            for key in data_dict:
                stored_record_internal = data_dict[key]
                stored_record_internal.decrypt(master_password)
                if stored_record_internal.service == service and stored_record_internal.username == username:
                    print "\nYou have already added an entry for the given username with the given service"
                    print "\n                         Record not added, PLEASE TRY AGAIN\n"
                    add_data()
                
        if fileread(master_username + "CTR", data_directory):
            for key in data_dict:
                stored_record_internal = data_dict[key]
                stored_record_internal.decrypt(master_password)
                if stored_record_internal.service == service and stored_record_internal.username == username:
                    print "You have already added an entry for the given username with the given service"
                    print "\n                         RECORD NOT ADDED, PLEASE TRY AGAIN\n"
                    add_data()

        new_record = classdef.record(service, username, password, mode)
        new_record.encrypt(master_password)
        new_record.write(master_username + mode, data_directory)
        print "\n         The above entry has been ADDED TO YOUR DATABASE.\n"
        task = raw_input("\nEnter 1: Add more entries OR 2: Home Screen OR (Any Other key): Log Out :- ")
        if task == "1":
            add_data()
        elif task == "2":
            authenticated_user()
        else:
            print "\n        You have successfully LOGGED OUT of your account"
            sys.exit(0)
            
    elif v == "2":
        print "\n                    RECORD NOT ADDED\n"
        add_data()
        
    elif v == "3":
        authenticated_user()
        
    else:
        print "\n        You have successfully LOGGED OUT of your account"
        sys.exit(0)


##################################################################
# This function gets data from the file for an authenticated user
##################################################################
def get_data():
    print "\n\n                    Stored Records for %s\n" % master_username
    n = 0
    if fileread(master_username + "ECB", data_directory):
        n = n + 1
        for key in data_dict:
            stored_record_internal = data_dict[key]
            stored_record_internal.decrypt(master_password)
            print "\nYour credentials for %s are:" % stored_record_internal.service
            print "username = %s" % stored_record_internal.username
            print "password = %s" % stored_record_internal.password
            print "mode = %s" % stored_record_internal.mode

    if fileread(master_username + "CBC", data_directory):
        n = n + 1
        for key in data_dict:
            stored_record_internal = data_dict[key]
            stored_record_internal.decrypt(master_password)
            print "\nYour credentials for %s are:" % stored_record_internal.service
            print "username = %s" % stored_record_internal.username
            print "password = %s" % stored_record_internal.password
            print "mode = %s" % stored_record_internal.mode
            
    if fileread(master_username + "CTR", data_directory):
        n = n + 1
        for key in data_dict:
            stored_record_internal = data_dict[key]
            stored_record_internal.decrypt(master_password)
            print "\nYour credentials for %s are:" % stored_record_internal.service
            print "username = %s" % stored_record_internal.username
            print "password = %s" % stored_record_internal.password
            print "mode = %s" % stored_record_internal.mode

    if n == 0:
        print "You have not saved any data yet"
        authenticated_user()
    
    print "\n                            END OF RECORDS"
    authenticated_user()


##################################################################
# Function for an authenticated user
##################################################################
def authenticated_user():
    print "\n\n                           Home Screen\n"
    action = raw_input("Enter 1: Add data to your database OR 2: Read data from your database OR 3: Log Out :- ")
    
    if action == "1":
        add_data()
   
    elif action == "2":
        get_data()
    
    elif action == "3":
        print "\n        You have successfully LOGGED OUT of your account"
        sys.exit(0)
        
    else:
        print "\n           Please enter a relevant action number."
        authenticated_user()
        
    return


##################################################################
# The Function below signs up the user to the Master Password App
##################################################################
def user_signup():
    print "\n\n                       Sign Up Screen\n"
    global master_username
    global master_password
    master_username = raw_input("Enter the App Username or the Master Username: ")
    master_username = master_username.lower()
    if fileread("masterdata", code_directory):
        for key in data_dict:
            if data_dict[key].username == master_username:
                print "\nThe username already exists. PLEASE TRY AGAIN"
                return
   
    master_password = getpass.getpass(prompt = "Enter the App Password or the Master Password: ")
    c_master_password = getpass.getpass(prompt = "Confirm the App Password or the Master Password: ")
    if master_password != c_master_password:
        print "The values of the fields in Password and Confirm password do not match. PLEASE TRY AGAIN"
        return
    master_record = classdef.record("Password manager", master_username, master_password, "ECB")
    master_record.encrypt(master_password, 1)
    master_record.write("masterdata", code_directory)
    print "\nYou've successfully signed up for the App. Please login to continue\n"
    user_login()
    return


##################################################################
# The Function below logs in the user to the Master Password App
##################################################################    
def user_login():
        print "\n\n                          Login Screen\n"
        global master_username
        global master_password
        master_username = raw_input("Enter the App Username or the Master Username: ")
        master_password = getpass.getpass(prompt = "Enter the App Password or the Master Password: ")
        if fileread("masterdata", code_directory):
            for key in data_dict:

                if data_dict[key].username == master_username:
                    global stored_record
                    stored_record = data_dict[key]
                    stored_record.decrypt(master_password, 1)
                    
                    hashed_master_password = hashed(master_password, stored_record.salt)
                    
                    if stored_record.password == hashed_master_password:
                        print "\nYou've successfully logged in the system"
                        authenticated_user()
                        return
                    else:
                        print "The username and password does not match. PLEASE TRY AGAIN"
                        return
        
        print "The username and password does not match. Please try again"          # Actually username doesn't exist at all here. (Diff comment for security)
        return