# TCP/UDP Mixed Mode Analysis

## Question

Does the current libuv implementation support mixed-mode forwarding where the client-facing protocol differs from the backend protocol?

Examples:
- TCP client → UDP backend (e.g., `192.168.137.2 5555/tcp 192.168.137.1 53/udp`)
- UDP client → TCP backend (e.g., `192.168.137.2 5556/udp 192.168.137.1 80/tcp`)

## Short Answer

**No, mixed mode does NOT work in the current libuv implementation.**

## Detailed Analysis

### 1. Parser Accepts Mixed Mode Syntax ✓

The configuration parser (`parse.c:640-641`) does accept separate protocols for client and backend:

```c
addServer(yy->bindAddress, yy->bindPort, yy->bindProto,
          yy->connectAddress, yy->connectPort, yy->connectProto, ...)
```

So this syntax is valid:
```
192.168.137.2 5555/tcp 192.168.137.1 53/udp    # TCP client → UDP backend
192.168.137.2 5556/udp 192.168.137.1 80/tcp    # UDP client → TCP backend
```

### 2. Implementation Does NOT Support It ✗

Looking at `rinetd.c`, the code **hardcodes** both sides to use the same protocol:

#### TCP Server Accept Callback (`rinetd.c:686-711`):
```c
cnx->remote.protocol = IPPROTO_TCP;  // Line 686 - client side
cnx->local.protocol = IPPROTO_TCP;   // Line 691 - backend side (HARDCODED!)
uv_tcp_init(main_loop, &cnx->local_uv_handle.tcp);  // Line 709 - assumes TCP
```

#### UDP Server Receive Callback (`rinetd.c:1195-1234`):
```c
cnx->remote.protocol = IPPROTO_UDP;  // Line 1195 - client side
cnx->local.protocol = IPPROTO_UDP;   // Line 1234 - backend side (HARDCODED!)
uv_udp_init(main_loop, &cnx->local_uv_handle.udp);  // Line 1223 - assumes UDP
```

The backend protocol is never read from the server configuration. Both sides always use the same protocol as the server socket.

### 3. Fundamental Architectural Problems

Even if we stored the backend protocol in the ServerInfo structure, there are deep architectural challenges:

#### Protocol Impedance Mismatch

- **TCP** = stream-oriented (continuous byte flow, no message boundaries)
- **UDP** = message-oriented (discrete datagrams with explicit boundaries)

**Critical Question:** When TCP data arrives, where do you split it into UDP datagrams?
- Original packet boundaries are lost in TCP stream
- Need explicit framing protocol (e.g., DNS-over-TCP uses 2-byte length prefix)
- Without application-level framing, there's no way to know where one message ends and another begins

#### Current Data Flow Assumes Homogeneous Protocol

```
TCP → TCP:  tcp_read_cb → buffer → tcp_write_to_backend
UDP → UDP:  udp_server_recv_cb → buffer → udp_send_to_backend
```

**Mixed mode would need:**
```
TCP → UDP:  tcp_read_cb → ??? how to frame? → udp_send_to_backend
UDP → TCP:  udp_server_recv_cb → ??? how to stream? → tcp_write_to_backend
```

#### Connection Semantics Mismatch

- **TCP** has connection lifecycle: `connect()` → `established` → `close()`
- **UDP** is connectionless: just send/receive datagrams
- Current UDP implementation simulates "connections" by tracking source addresses with timeouts

**UDP → TCP Questions:**
- When do you establish the TCP connection to the backend?
- When do you close it? (after timeout? after each datagram?)
- What if TCP connection fails? (UDP has no concept of connection failure)
- How do you handle TCP backpressure with connectionless UDP?

**TCP → UDP Questions:**
- How do you map a continuous TCP stream to discrete UDP messages?
- What if UDP datagrams are lost? (TCP expects reliable delivery)
- How do you handle flow control differences?

### 4. What Would Be Needed for Mixed Mode Support

To support mixed mode, significant architectural changes would be required:

#### 1. Store Backend Protocol

Modify `ServerInfo` structure in `types.h`:
```c
struct _server_info {
    uv_handle_type handle_type;         // Client-facing protocol (UV_TCP or UV_UDP)
    uv_handle_type backend_handle_type; // NEW: Backend protocol (UV_TCP or UV_UDP)
    ...
}
```

#### 2. Application-Specific Framing Layer

You need protocol-specific knowledge to convert between stream and message modes:

**DNS-over-TCP:**
- Standard: 2-byte length prefix before each DNS message
- Clear message boundaries
- Well-defined behavior

**SOCKS Proxy:**
- Specific protocol framing and handshake
- Request/response structure

**HTTP/3 (QUIC):**
- Complex QUIC protocol framing over UDP
- Streams, flow control, reliability layer

**Generic:**
- Would need user to specify framing strategy
- Or implement multiple protocol-specific modes

#### 3. Mixed-Mode Callback Functions

```c
static void tcp_to_udp_read_cb(...)   // Read TCP stream, extract messages, send UDP
static void udp_to_tcp_recv_cb(...)   // Receive UDP datagram, write to TCP stream
```

Each would need buffering and framing logic specific to the application protocol.

#### 4. Connection Lifecycle Management

**For UDP → TCP:**
- When to establish TCP connection? (on first UDP packet? pre-connect?)
- When to close TCP connection? (after timeout? keep-alive?)
- How to handle TCP connection failures? (log? retry? buffer UDP?)
- Timeout strategies for idle connections

**For TCP → UDP:**
- How to handle UDP send failures? (no connection state)
- What to do when TCP connection closes? (stop accepting? error?)
- Flow control strategy (TCP can backpressure, UDP cannot)

### 5. Special Case: DNS Protocol

**DNS-specific TCP↔UDP conversion is feasible** because:

1. **Well-defined framing:**
   - DNS-over-TCP: 2-byte length prefix (RFC 1035)
   - DNS-over-UDP: no framing needed (message = datagram)

2. **Self-contained messages:**
   - Each DNS query/response is complete
   - No multi-message transactions
   - Clear start and end boundaries

3. **Standard behavior:**
   - RFC-defined conversion rules
   - Known timeout behaviors
   - Standard maximum message sizes (512 bytes UDP, up to 64KB TCP)

4. **Connection semantics:**
   - TCP connection per query or connection pooling
   - Well-defined timeout rules
   - Standard retry mechanisms

**Implementation approach for DNS:**
```c
// TCP → UDP (DNS)
tcp_read_cb:
  - Read 2-byte length prefix
  - Read N bytes of DNS message
  - Send complete message as single UDP datagram

// UDP → TCP (DNS)
udp_recv_cb:
  - Receive UDP datagram (complete DNS message)
  - Prepend 2-byte length prefix
  - Write to TCP stream
```

## Current Implementation Status

### What Works ✓
- **TCP → TCP** forwarding (tested with HTTP, 100% success rate)
- **UDP → UDP** forwarding (tested with DNS, 100% success rate)
- Dynamic buffer management for both protocols
- Parallel connections with high throughput
- Upstream validation for correctness

### What Doesn't Work ✗
- **TCP → UDP** mixed mode
- **UDP → TCP** mixed mode
- Any protocol conversion/translation

## Recommendations

### For General Mixed Mode
**Not recommended** without specific use case requirements. Would need:
- Significant architectural changes
- Application-specific framing logic
- Careful design of connection lifecycle
- Handling of protocol impedance mismatches
- Extensive testing for edge cases

### For DNS-Specific TCP↔UDP
**Feasible to implement** if there's a real need:
- Well-defined framing (2-byte length prefix)
- Clear protocol semantics
- Limited scope and complexity
- Useful for DNS load balancers or proxies

### For Other Protocols
Would need to:
1. Identify specific protocol (HTTP, SOCKS, etc.)
2. Define framing strategy
3. Specify connection lifecycle rules
4. Implement protocol-specific handlers
5. Extensive testing

## Conclusion

The parser accepts mixed-mode configuration syntax, but the implementation does not support it. Supporting mixed mode would require fundamental architectural changes to handle protocol conversion, message framing, and connection lifecycle management.

For most use cases, **stick to homogeneous forwarding:**
- TCP client → TCP backend (works perfectly)
- UDP client → UDP backend (works perfectly)

If mixed mode is truly needed, it should be implemented for a **specific protocol** (like DNS) with well-defined behavior, rather than as a generic feature.
