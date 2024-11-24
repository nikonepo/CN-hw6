package main

import (
    "bytes"
    "context"
    "encoding/json"
    "flag"
    "fmt"
    "github.com/florianl/go-nfqueue"
    "github.com/mdlayher/netlink"
    "os"
    "strings"
    "time"
)

type Rule struct {
    Type       string
    Host       string
    Method     string
    UserAgent  string
    PathPrefix string
    ContentLen int
}

func main() {
    fileName := flag.String("file", "rules.json", "File with rules")

    flag.Parse()

    rules := parseRules(fileName)

    config := nfqueue.Config{
        NfQueue:      100,
        MaxPacketLen: 0xFFFF,
        MaxQueueLen:  0xFF,
        Copymode:     nfqueue.NfQnlCopyPacket,
        WriteTimeout: 15 * time.Millisecond,
    }
    nf, err := nfqueue.Open(&config)
    if err != nil {
        fmt.Println("could not open nfqueue socket:", err)
        return
    }

    defer nf.Close()
    if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
        fmt.Printf("failed to set netlink option %v: %v\n",
            netlink.NoENOBUFS, err)
        return
    }

    ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
    defer cancel()

    fn := func(a nfqueue.Attribute) int {
        id := *a.PacketID
        payload := *a.Payload

        httpData, err := extractHTTPPayload(payload)
        if err != nil {
            nf.SetVerdict(id, nfqueue.NfAccept)
            return 0
        }

        if checkPacket(httpData, rules) {
            nf.SetVerdict(id, nfqueue.NfDrop)
        } else {
            nf.SetVerdict(id, nfqueue.NfAccept)
        }

        return 0
    }

    err = nf.RegisterWithErrorFunc(ctx, fn, func(e error) int {
        fmt.Println(err)
        return -1
    })

    if err != nil {
        fmt.Println(err)
        return
    }

    <-ctx.Done()
}

func extractHTTPPayload(payload []byte) ([]byte, error) {
    ipHeaderLen := (payload[0] & 0x0F) * 4
    tcpHeaderOffset := ipHeaderLen
    tcpHeaderLen := (payload[tcpHeaderOffset+12] >> 4) * 4

    httpPayload := payload[tcpHeaderOffset+tcpHeaderLen:]
    if len(httpPayload) == 0 || !bytes.HasPrefix(httpPayload, []byte("GET")) &&
        !bytes.HasPrefix(httpPayload, []byte("POST")) &&
        !bytes.HasPrefix(httpPayload, []byte("PUT")) {

        return nil, fmt.Errorf("not HTTP pacekt")
    }

    return httpPayload, nil
}

func parseRules(fileName *string) []Rule {
    file, err := os.ReadFile(*fileName)
    if err != nil {
        fmt.Printf("Failed to read file: %v\n", err)
        return make([]Rule, 0)
    }

    var rules []Rule

    err = json.Unmarshal(file, &rules)
    if err != nil {
        fmt.Printf("Failed to parse rules: %v\n", err)
        return make([]Rule, 0)
    }

    return rules
}

func checkPacket(packet []byte, rules []Rule) bool {
    lines := strings.Split(string(packet), "\r\n")
    if len(lines) < 2 {
        return false
    }

    requestLine := lines[0]
    headers := parseHeaders(lines[1:])

    parts := strings.Split(requestLine, " ")
    if len(parts) < 2 {
        return false
    }
    method := parts[0]
    path := parts[1]
    contentLen := parseContentLength(headers["Content-Length"])

    for _, rule := range rules {
        if rule.Method != "" && rule.Method != method {
            continue
        }

        if rule.PathPrefix != "" && !strings.HasPrefix(path, rule.PathPrefix) {
            continue
        }

        if rule.Host != "" && rule.Host != headers["Host"] {
            continue
        }

        if rule.UserAgent != "" && !strings.Contains(headers["User-Agent"], rule.UserAgent) {
            continue
        }

        if rule.ContentLen > 0 && contentLen > rule.ContentLen {
            continue
        }

        return rule.Type == "delete"
    }

    return false
}

func parseHeaders(headerLines []string) map[string]string {
    headers := make(map[string]string)
    for _, line := range headerLines {
        parts := strings.SplitN(line, ": ", 2)
        if len(parts) == 2 {
            headers[parts[0]] = parts[1]
        }
    }
    return headers
}

func parseContentLength(contentLenStr string) int {
    if contentLenStr == "" {
        return 0
    }
    var contentLen int
    fmt.Sscanf(contentLenStr, "%d", &contentLen)
    return contentLen
}
