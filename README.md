# yoohoo

Pure Go implementation of the FTS-0006 YooHoo/2U2 handshake — the FidoNet mail-session handshake Opus-CBCS introduced and WaZOO-capable mailers still answer.

This is a library package — there is no CLI. It runs the handshake on an established connection (a modem line, a TCP socket) and reports what the two systems agreed on. The file transfer that follows is not part of this package.

YooHoo replaces FTS-0001's TSYNC synchronisation with a 128-byte "hello" exchanged in each direction. A hello carries the system's address, name and sysop, an 8-byte session password, and a capability mask from which one session method is chosen: ZedZap, ZedZip (plain ZMODEM), DietIFNA (FTS-0001 transfers), Janus or Hydra.

## Features

- Caller side (`Call`) and answerer side (`Answer`), with the FTS-0006 timers as configurable defaults
- The hello codec on its own: `Hello.Marshal`, `ParseHello`, `Frame`, `CheckFrame` (CRC-16), for tools that only need to read or build one
- Method choice in the FTS-0006 order — Janus, ZedZap, ZedZip, DietIFNA — with Hydra, a field extension the spec does not list, placed first (`ChooseMethod`); the called system decides
- Session passwords the way the field compares them: eight bytes, case-insensitive (`PasswordMatch`, `WirePassword`)
- Domains: a domain name carried after the system name's NUL when `CapDomain` is set
- A refusal completes the exchange, so the caller learns it was refused
- Bytes read past the end of the handshake are not lost: `Result.Conn` replays them ahead of the live connection for the transfer phase
- Tolerates the Opus habit of answering every stray byte with ENQ
- Standard library only; no dependencies
- Interoperable with Opus

## Install

```
go get github.com/xx25/go-yoohoo
```

## Usage

```go
package main

import (
	"errors"
	"log"
	"net"

	"github.com/xx25/go-yoohoo"
)

func main() {
	conn, err := net.Dial("tcp", "node.example.org:60179")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	res, err := yoohoo.Call(conn, yoohoo.Config{
		Local: yoohoo.Hello{
			SystemName:   "Example System",
			Sysop:        "Sysop Name",
			Zone:         999,
			Net:          1,
			Node:         2,
			Capabilities: yoohoo.CapZedZap | yoohoo.CapZedZip,
		},
		Password: "secret",
	})
	switch {
	case errors.Is(err, yoohoo.ErrNoMethod):
		log.Fatalf("%s shares no session method with us", res.Remote.Address())
	case err != nil:
		log.Fatal(err)
	}

	log.Printf("connected to %s (%s), method %s",
		res.Remote.Address(), res.Remote.SystemName, yoohoo.MethodName(res.Method))

	// Run the transfer phase on res.Conn, not on conn: it carries any
	// bytes the peer sent right behind the handshake.
	_ = res.Conn
}
```

The answering side calls `yoohoo.Answer(conn, cfg, yoohooPending)` with an `Authorize` function in its `Config`. `Authorize` sees the caller's hello and returns the password to echo and whether the session may go on. `yoohooPending` says whether the caller's opening YOOHOO byte is still unread on the connection (true) or was already consumed by whatever recognised the handshake (false).

## Configuration

Zero values take the FTS-0006 defaults.

| Field | Meaning | Default |
|---|---|---|
| `Local` | Our hello: identity, address, capabilities | — |
| `Password` | Caller: the session secret for this peer (`""` or `"-"` = none) | none |
| `Authorize` | Answerer: judges the caller's hello | accept everyone |
| `Logger` | Debug line per state transition | none |
| `SyncTimeout` | Caller: wait for ENQ after each YOOHOO | 3 s |
| `MasterTimeout` | Caller: bound on the whole synchronisation | 60 s |
| `HelloAckTimeout` | Wait for ACK of a sent hello | 40 s |
| `HelloWait` | Caller: wait for the answerer's YOOHOO | 30 s |
| `ENQWait` | Answerer: wait for ENQ after its YOOHOO | 20 s |
| `HeaderWait` | Wait for the hello's start byte before repeating ENQ | 10 s |
| `BodyTimeout` | Bound on reading a hello | 30 s |
| `MaxRetries` | Cap on every retried step: the caller's YOOHOO, sending a hello, receiving one (the answerer's own YOOHOO is tried three times, fixed) | 10 |

## Sentinel errors

| Error | Meaning |
|---|---|
| `ErrCarrierLost` | The connection dropped during the handshake |
| `ErrNoENQ` | The peer never answered our YOOHOO |
| `ErrNoACK` | Our hello was not acknowledged |
| `ErrNoYooHoo` | The peer acknowledged our hello but sent none of its own |
| `ErrNoHello` | The peer's hello never arrived intact |
| `ErrNoMethod` | No session method in common; the `Result` is still returned |
| `ErrRefused` | The session was refused (password or capabilities); the `Result` is still returned |
| `ErrShortHello` | `ParseHello`, `CheckFrame`: fewer than 128 bytes |

All are matched with `errors.Is`. `CheckFrame` reports a CRC mismatch as a plain error.

`Call` and `Answer` take no context: every wait has its own timer and every retried step is capped by `MaxRetries`, so they always end, but the worst case is minutes. To stop one early, close the connection.

## Security

- **The password is not secret on the wire.** FTS-0006 sends the 8-byte session password in the clear in both directions, and the answerer echoes it. It identifies a peer on a trusted line; it does not protect one on an open network.
- **A hello is the peer's claim.** Address, name and sysop are whatever the remote side wrote. Decide in `Authorize` what a claimed address is allowed to do.
- **Only eight bytes count.** Longer configured secrets are truncated by the wire format, and comparison ignores case.

## License

MIT — see [LICENSE](LICENSE).
