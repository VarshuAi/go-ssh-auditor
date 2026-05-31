package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	hostFile := flag.String("h", "hosts.txt", "File containing target SSH hosts (ip:port)")
	credsFile := flag.String("c", "creds.txt", "File containing credentials in user:pass format")
	threads := flag.Int("t", 10, "Number of concurrent auditing threads")
	flag.Parse()

	hosts := readLines(*hostFile)
	creds := readLines(*credsFile)

	if len(hosts) == 0 || len(creds) == 0 {
		fmt.Println("[-] Please provide valid hosts (-h) and credentials (-c) files.")
		return
	}

	fmt.Printf("[*] Starting audit on %d hosts with %d credentials using %d threads...\n", len(hosts), len(creds), *threads)

	jobs := make(chan auditJob, 100)
	var wg sync.WaitGroup

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				auditHost(job.host, job.user, job.pass)
			}
		}()
	}

	for _, host := range hosts {
		if !strings.Contains(host, ":") {
			host = host + ":22"
		}
		for _, cred := range creds {
			parts := strings.Split(cred, ":")
			if len(parts) != 2 {
				continue
			}
			jobs <- auditJob{host: host, user: parts[0], pass: parts[1]}
		}
	}
	close(jobs)
	wg.Wait()
	fmt.Println("[+] SSH Auditing process completed.")
}

type auditJob struct {
	host, user, pass string
}

func auditHost(host, user, pass string) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", host, config)
	if err == nil {
		defer client.Close()
		fmt.Printf("[+] SUCCESS! Credential found on %s -> %s:%s\n", host, user, pass)
		// Save success log
		f, _ := os.OpenFile("ssh_audit_success.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		defer f.Close()
		f.WriteString(fmt.Sprintf("%s -> %s:%s\n", host, user, pass))
	}
}

func readLines(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return []string{}
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}