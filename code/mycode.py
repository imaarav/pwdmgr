import sys
sys.path.append("../pycrypto/lib")

from Classdefinition import classdef
from Functions import functions


def main():
    
    print "\n\n                        PASSWORD MANAGER\n\n"
    initial = raw_input("Enter 1 to Sign up OR 2 to Login: ")
    if initial == "1":
        functions.user_signup()
    elif initial == "2":
        functions.user_login()
    else:
        print "\n                  Please enter relevant data"
        main()

    
if __name__ == '__main__':
    main()
