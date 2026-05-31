# Go SSH Auditor
A parallel SSH credential auditor and configuration scanner built in Go. Ideal for cybersecurity auditing and checking host strengths in Termux or Linux CLI.

## Installation
```bash
go build -o ssh-auditor main.go
```

## Usage
```bash
./ssh-auditor -h hosts.txt -c creds.txt -t 20
```