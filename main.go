package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const version = "1.0.0"

const banner = `███████████    ███████    █████   █████    ███████    ███████████
▒█▒▒▒▒▒▒███   ███▒▒▒▒▒███ ▒▒███   ▒▒███   ███▒▒▒▒▒███ ▒█▒▒▒▒▒▒███ 
▒     ███▒   ███     ▒▒███ ▒███    ▒███  ███     ▒▒███▒     ███▒  
     ███    ▒███      ▒███ ▒███    ▒███ ▒███      ▒███     ███    
    ███     ▒███      ▒███ ▒▒███   ███  ▒███      ▒███    ███     
  ████     █▒▒███     ███   ▒▒▒█████▒   ▒▒███     ███   ████     █
 ███████████ ▒▒▒███████▒      ▒▒███      ▒▒▒███████▒   ███████████
▒▒▒▒▒▒▒▒▒▒▒    ▒▒▒▒▒▒▒         ▒▒▒         ▒▒▒▒▒▒▒    ▒▒▒▒▒▒▒▒▒▒▒`

type Result struct {
	URL        string `json:"url"`
	Status     string `json:"status"`
	HTTPStatus int    `json:"http_status,omitempty"`
	CNAME      string `json:"cname,omitempty"`
	Reason     string `json:"reason"`
}

type Config struct {
	timeout time.Duration
}

func color(s, code string) string { return "\033[" + code + "m" + s + "\033[0m" }

func printBanner() {
	lines := strings.Split(banner, "\n")
	for i, line := range lines {
		if i < 4 {
			fmt.Println(color(line, "31"))
		} else {
			fmt.Println(color(line, "97"))
		}
	}
	fmt.Println("create by:Raxxt")
	fmt.Println()
}

func usage() {
	printBanner()
	fmt.Println("Penggunaan:")
	fmt.Println("  zovoz -u https://sub.example.com       Scan satu subdomain")
	fmt.Println("  zovoz -d example.com                   Enumerasi subdomain via crt.sh lalu scan")
	fmt.Println("  zovoz -l subdomains.txt                Scan daftar subdomain dari file")
	fmt.Println("  zovoz -l subdomains.txt -o hasil.txt   Simpan semua hasil ke file")
	fmt.Println("  zovoz -l subdomains.txt --live         Tampilkan kandidat saja setelah scan")
	fmt.Println()
	fmt.Println("Opsi:")
	fmt.Println("  -h, --help       Menampilkan bantuan")
	fmt.Println("  --version        Menampilkan versi")
	fmt.Println("  -u URL           URL/subdomain tunggal")
	fmt.Println("  -d DOMAIN        Domain dasar untuk enumerasi crt.sh")
	fmt.Println("  -l FILE          File berisi satu host/URL per baris")
	fmt.Println("  -o FILE          File output hasil scan (JSON Lines)")
	fmt.Println("  -f FILE          Alias -o, untuk menyimpan hasil scan")
	fmt.Println("  --live           Hanya tampilkan kandidat takeover setelah scan")
	fmt.Println("  --timeout SEC    Timeout per request (default 8)")
	fmt.Println("  --workers N      Jumlah worker (default 5)")
	fmt.Println()
	fmt.Println("Catatan: 'mungkin bisa di-takeover' adalah indikasi awal, bukan bukti.")
	fmt.Println("Gunakan hanya pada domain yang Anda miliki atau punya izin tertulis.")
}

func normalizeTarget(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" { return "", "", errors.New("target kosong") }
	if !strings.Contains(raw, "://") { raw = "https://" + raw }
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" { return "", "", errors.New("URL/host tidak valid") }
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if strings.Contains(host, "*") || strings.Contains(host, " ") { return "", "", errors.New("hostname tidak valid") }
	if u.Scheme != "http" && u.Scheme != "https" { return "", "", errors.New("hanya HTTP/HTTPS yang didukung") }
	return u.String(), host, nil
}

func enumerate(domain string, timeout time.Duration) ([]string, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimSuffix(strings.Split(domain, "/")[0], ".")
	if domain == "" || strings.Contains(domain, " ") { return nil, errors.New("domain tidak valid") }

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://crt.sh/?q=%25."+url.QueryEscape(domain)+"&output=json", nil)
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil { return nil, fmt.Errorf("gagal mengambil data crt.sh: %w", err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return nil, fmt.Errorf("crt.sh mengembalikan HTTP %d", resp.StatusCode) }
	var rows []struct { NameValue string `json:"name_value"` }
	if err := json.NewDecoder(io.LimitReader(resp.Body, 15<<20)).Decode(&rows); err != nil { return nil, fmt.Errorf("gagal membaca data crt.sh: %w", err) }
	seen := map[string]bool{}
	var out []string
	for _, row := range rows {
		for _, name := range strings.Split(row.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimPrefix(name, "*.")
			if name == domain || strings.HasSuffix(name, "."+domain) {
				if !seen[name] { seen[name] = true; out = append(out, name) }
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func readTargets(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil { return nil, err }
	defer f.Close()
	seen := map[string]bool{}
	var targets []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") { continue }
		_, host, err := normalizeTarget(s)
		if err != nil { fmt.Fprintf(os.Stderr, "[skip] %s: %v\n", s, err); continue }
		if !seen[host] { seen[host] = true; targets = append(targets, s) }
	}
	return targets, sc.Err()
}

func providerHint(body, cname string) string {
	s := strings.ToLower(body + " " + cname)
	checks := []struct{ marker, hint string }{
		{"no such app", "indikasi aplikasi tidak ditemukan pada platform hosting"},
		{"there isn't a github pages site here", "indikasi konfigurasi GitHub Pages tidak ditemukan"},
		{"the thing you were looking for is no longer here", "indikasi resource tidak ditemukan pada platform hosting"},
		{"project not found", "indikasi project hosting tidak ditemukan"},
		{"site not found", "indikasi situs tidak ditemukan pada platform hosting"},
		{"unknown domain", "indikasi domain tidak dikenali oleh layanan tujuan"},
		{"domain is not configured", "indikasi domain belum dikonfigurasi pada layanan tujuan"},
		{"herokucdn.com/error-pages", "indikasi halaman error Heroku"},
		{"cloudfront.net", "CNAME mengarah ke CloudFront; periksa konfigurasi distribusi"},
		{"azurewebsites.net", "CNAME mengarah ke Azure App Service; perlu verifikasi resource"},
		{"github.io", "CNAME mengarah ke GitHub Pages; perlu verifikasi konfigurasi"},
		{"amazonaws.com", "CNAME mengarah ke layanan AWS; perlu verifikasi resource"},
		{"readme.io", "CNAME mengarah ke layanan ReadMe; perlu verifikasi konfigurasi"},
		{"zendesk.com", "CNAME mengarah ke Zendesk; perlu verifikasi konfigurasi"},
	}
	for _, c := range checks { if strings.Contains(s, c.marker) { return c.hint } }
	return ""
}

func check(target string, cfg Config) Result {
	normalized, host, err := normalizeTarget(target)
	if err != nil { return Result{URL: target, Status: "ERROR", Reason: err.Error()} }
	r := Result{URL: normalized, Status: "AKTIF", Reason: "HTTP response diterima; tidak ada indikator takeover yang dikenali"}
	cname, dnsErr := net.LookupCNAME(host)
	if dnsErr == nil && cname != "" && !strings.EqualFold(strings.TrimSuffix(cname, "."), host) {
		r.CNAME = strings.TrimSuffix(cname, ".")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: (&net.Dialer{Timeout: cfg.timeout, KeepAlive: 15*time.Second}).DialContext,
		TLSHandshakeTimeout: cfg.timeout,
		ResponseHeaderTimeout: cfg.timeout,
	}
	client := &http.Client{
		Timeout: cfg.timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 { return http.ErrUseLastResponse }
			return nil
		},
	}
	req, _ := http.NewRequest(http.MethodGet, normalized, nil)
	req.Header.Set("User-Agent", "ZOVOZ-Subdomain-Audit/"+version+" (authorized defensive scanner)")
	resp, reqErr := client.Do(req)
	if reqErr != nil {
		// Retry HTTP only when the initial HTTPS connection fails.
		if strings.HasPrefix(normalized, "https://") {
			httpURL := "http://" + strings.TrimPrefix(normalized, "https://")
			req2, _ := http.NewRequest(http.MethodGet, httpURL, nil)
			req2.Header.Set("User-Agent", "ZOVOZ-Subdomain-Audit/"+version)
			resp, reqErr = client.Do(req2)
			if reqErr == nil { r.URL = httpURL }
		}
	}
	if reqErr != nil {
		if dnsErr != nil {
			r.Status = "ERROR"
			r.Reason = "DNS gagal dan HTTP tidak dapat dijangkau: " + reqErr.Error()
		} else {
			r.Status = "ERROR"
			r.Reason = "HTTP tidak dapat dijangkau: " + reqErr.Error()
		}
		if r.CNAME != "" && dnsErr == nil {
			r.Status = "MUNGKIN_TAKEOVER"
			r.Reason = "CNAME ditemukan tetapi endpoint tidak dapat dijangkau; perlu verifikasi manual"
		}
		return r
	}
	defer resp.Body.Close()
	r.HTTPStatus = resp.StatusCode
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	body := string(bodyBytes)
	hint := providerHint(body, r.CNAME)

	if resp.StatusCode == http.StatusNotFound {
		r.Status = "404"
		r.Reason = "HTTP 404; status ini saja tidak membuktikan subdomain dapat diambil alih"
	} else if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		r.Status = "AKTIF"
		r.Reason = "HTTP response diterima; layanan merespons"
	} else {
		r.Status = "ERROR"
		r.Reason = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	if hint != "" && (r.CNAME != "" || resp.StatusCode == 404 || resp.StatusCode >= 400) {
		r.Status = "MUNGKIN_TAKEOVER"
		r.Reason = hint + "; indikasi saja, verifikasi manual diperlukan"
	}
	return r
}

func main() {
	var u, domain, list, output string
	var live, showVersion bool
	var timeoutSec, workers int
	flag.StringVar(&u, "u", "", "URL/subdomain tunggal")
	flag.StringVar(&domain, "d", "", "enumerasi subdomain dari domain")
	flag.StringVar(&list, "l", "", "file daftar subdomain")
	flag.StringVar(&output, "o", "", "file output")
	flag.StringVar(&output, "f", "", "alias file output")
	flag.BoolVar(&live, "live", false, "tampilkan kandidat takeover saja")
	flag.BoolVar(&showVersion, "version", false, "versi tool")
	flag.IntVar(&timeoutSec, "timeout", 8, "timeout per request dalam detik")
	flag.IntVar(&workers, "workers", 5, "jumlah worker")
	flag.Usage = usage
	flag.Parse()

	if showVersion { fmt.Printf("ZOVOZ %s\n", version); return }
	if u == "" && domain == "" && list == "" { usage(); return }
	if timeoutSec < 1 { fmt.Fprintln(os.Stderr, "timeout harus >= 1"); os.Exit(2) }
	if workers < 1 { workers = 1 }; if workers > 20 { workers = 20 }
	printBanner()

	var targets []string
	var err error
	switch {
	case u != "":
		targets = []string{u}
	case list != "":
		targets, err = readTargets(list)
	case domain != "":
		var hosts []string
		hosts, err = enumerate(domain, time.Duration(timeoutSec)*time.Second)
		for _, h := range hosts { targets = append(targets, "https://"+h) }
	}
	if err != nil { fmt.Fprintln(os.Stderr, "Gagal menyiapkan target:", err); os.Exit(1) }
	if len(targets) == 0 { fmt.Println("Tidak ada target yang dapat dipindai."); return }

	var outFile *os.File
	if output != "" {
		outFile, err = os.Create(output)
		if err != nil { fmt.Fprintln(os.Stderr, "Gagal membuat file output:", err); os.Exit(1) }
		defer outFile.Close()
	}

	fmt.Println(color("Scanning sedang berlangsung...", "97"))
	fmt.Println("\nChecking:")
	cfg := Config{timeout: time.Duration(timeoutSec)*time.Second}
	type job struct{ target string }
	jobs := make(chan job)
	results := make(chan Result)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs { results <- check(j.target, cfg) }
		}()
	}
	go func() { for _, t := range targets { jobs <- job{t} }; close(jobs); wg.Wait(); close(results) }()

	var all []Result
	for r := range results { all = append(all, r) }
	sort.Slice(all, func(i,j int) bool { return all[i].URL < all[j].URL })
	for _, r := range all {
		if live && r.Status != "MUNGKIN_TAKEOVER" { continue }
		line := fmt.Sprintf("%s (%s) - %s", r.URL, r.Status, r.Reason)
		switch r.Status {
		case "MUNGKIN_TAKEOVER": fmt.Println(color(line, "31"))
		case "AKTIF": fmt.Println(color(line, "32"))
		case "404": fmt.Println(color(line, "33"))
		default: fmt.Println(color(line, "97"))
		}
		if outFile != nil {
			b, _ := json.Marshal(r)
			if _, err := outFile.Write(append(b, '\n')); err != nil { fmt.Fprintln(os.Stderr, "Gagal menulis output:", err) }
		}
	}
	candidates := 0
	for _, r := range all { if r.Status == "MUNGKIN_TAKEOVER" { candidates++ } }
	fmt.Printf("\nSelesai. Target: %d | Kandidat perlu verifikasi: %d\n", len(all), candidates)
	if live { fmt.Println("Mode --live aktif: hanya kandidat yang ditampilkan di layar.") }
	fmt.Println("Penting: tool ini tidak mendaftarkan domain atau melakukan takeover.")
}
