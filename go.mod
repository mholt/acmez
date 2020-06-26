module github.com/mholt/acme

go 1.14

require (
	github.com/cenkalti/backoff/v4 v4.0.2
	github.com/google/go-cmp v0.5.0 // indirect
	github.com/libdns/libdns v0.0.0-20200501023120-186724ffc821
	github.com/miekg/dns v1.1.29
	github.com/stretchr/testify v1.6.1
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/net v0.0.0-20200625001655-4c5254603344
	gopkg.in/square/go-jose.v2 v2.5.1
)

replace github.com/caddyserver/caddy/v2 => ../caddyserver/caddy

replace github.com/mholt/acme => ./
