// smoke.c — proves libhop's C ABI runs the real Hop protocol end to end, in pure C.
//
// Two in-memory nodes (A, B) are wired by a "loopback bearer": each node's drained outbound bytes
// are fed straight into the other's hop_bytes_received. We pump that loop while ticking the clock,
// which carries the Noise handshake + §25 prekey gossip; then A sends B an untraceable (§39) message
// and we poll B's inbox until it arrives. No radio, no Swift/Kotlin — just hop.h.
//
// Build+run is driven by smoke.sh.

#include "hop.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// A pump endpoint: feed bytes drained from one node into the peer node on link id 1.
typedef struct { const HopNode *peer; } Pipe;

static void forward(void *ctx, uint64_t link, const uint8_t *bytes, size_t len) {
    (void)link;
    Pipe *p = (Pipe *)ctx;
    hop_bytes_received(p->peer, 1, bytes, len);  // each node has exactly one link, id 1
}

// Inbox capture.
typedef struct { int got; char text[256]; uint8_t hops; } Inbox;

static bool on_message(void *ctx, const uint8_t *inbox_id, const uint8_t *from,
                       const char *content_type, const uint8_t *body, size_t body_len,
                       uint8_t hops, uint64_t created_at) {
    (void)inbox_id; (void)from; (void)content_type; (void)created_at;
    Inbox *in = (Inbox *)ctx;
    size_t n = body_len < sizeof(in->text) - 1 ? body_len : sizeof(in->text) - 1;
    memcpy(in->text, body, n);
    in->text[n] = '\0';
    in->hops = hops;
    in->got = 1;
    return true;
}

// hops:// host-side: capture one inbound service request (so we can seal a reply to its caller).
typedef struct { int got, answered; uint8_t from[32], req_id[32]; char service[64], method[64]; } ReqCap;

static void on_request(void *ctx, const uint8_t *from, const uint8_t *request_id,
                       const char *service, const char *method, const uint8_t *args, size_t args_len) {
    (void)args; (void)args_len;
    ReqCap *r = (ReqCap *)ctx;
    if (r->got) return;
    memcpy(r->from, from, 32); memcpy(r->req_id, request_id, 32);
    snprintf(r->service, sizeof(r->service), "%s", service);
    snprintf(r->method, sizeof(r->method), "%s", method);
    r->got = 1;
}

// hops:// caller-side: capture the response sealed back to us.
typedef struct { int got; uint16_t status; char body[256]; } RespCap;

static bool on_response(void *ctx, const uint8_t *from, const uint8_t *for_request_id,
                        uint16_t status, const uint8_t *body, size_t body_len) {
    (void)from; (void)for_request_id;
    RespCap *r = (RespCap *)ctx;
    size_t n = body_len < sizeof(r->body) - 1 ? body_len : sizeof(r->body) - 1;
    memcpy(r->body, body, n); r->body[n] = '\0';
    r->status = status; r->got = 1;
    return true;
}

int main(void) {
    const HopNode *a = hop_node_new();
    const HopNode *b = hop_node_new();
    if (!a || !b) { printf("FAIL: node create\n"); return 1; }

    uint64_t now = 1700000000000ULL;  // a real clock so prekey adverts aren't judged expired
    hop_node_tick(a, now);
    hop_node_tick(b, now);
    hop_publish_prekey(a);
    hop_publish_prekey(b);

    uint8_t b_addr[32];
    if (!hop_node_address(b, b_addr)) { printf("FAIL: address\n"); return 1; }

    // Link up: A dialed (initiator), B accepted (responder). Same link id 1 each side.
    hop_link_up(a, 1, HopLinkRole_Dialer);
    hop_link_up(b, 1, HopLinkRole_Acceptor);

    Pipe to_b = { b }, to_a = { a };
    Inbox inbox = { 0 };

    // Pump the handshake + prekey gossip a bit before sending.
    for (int i = 0; i < 50; i++) {
        hop_drain_outgoing(a, forward, &to_b);
        hop_drain_outgoing(b, forward, &to_a);
        now += 100; hop_node_tick(a, now); hop_node_tick(b, now);
    }

    uint8_t msg_id[32];
    const char *text = "hello over the C ABI";
    // request_ack=1 so B seals a private delivery-ACK back to A (§39) — proves the return path too.
    if (!hop_send_message(a, b_addr, "text/plain", (const uint8_t *)text, strlen(text), 1, msg_id)) {
        printf("FAIL: send_message returned false\n"); return 1;
    }

    // Pump until B receives it AND A sees it delivered (the ACK flowed back), or we give up.
    bool delivered = false; uint32_t relayed = 0, ms = 0; uint8_t dhops = 0;
    for (int i = 0; i < 400 && !(inbox.got && delivered); i++) {
        hop_drain_outgoing(a, forward, &to_b);
        hop_drain_outgoing(b, forward, &to_a);
        hop_poll_inbox(b, on_message, &inbox);
        hop_message_status(a, msg_id, &relayed, &delivered, &dhops, &ms);
        now += 100; hop_node_tick(a, now); hop_node_tick(b, now);
    }

    int ok = inbox.got && strcmp(inbox.text, text) == 0 && delivered;
    printf("%s: B inbox got=%d text=\"%s\" hops=%u | A sees delivered=%d fwd_hops=%u\n",
           ok ? "PASS" : "FAIL", inbox.got, inbox.text, inbox.hops, delivered, dhops);

    // Exercise the base58 round-trip helper too.
    char b58[64]; uint8_t back[32];
    size_t blen = hop_address_to_base58(b_addr, b58, sizeof(b58));
    int b58_ok = blen > 0 && hop_address_from_base58(b58, back) && memcmp(b_addr, back, 32) == 0;
    printf("%s: base58 round-trip (%s)\n", b58_ok ? "PASS" : "FAIL", b58);

    // hops:// FULL round trip: A requests a service B hosts; B replies; A reads the response.
    // (Unlike the datagram above, this needs HDP in BOTH directions.)
    uint8_t reqId[32];
    const char *args = "zip=80202";
    hop_send_service_request(a, b_addr, "weather", "report", (const uint8_t *)args, strlen(args), reqId);
    ReqCap req = {0}; RespCap resp = {0};
    for (int i = 0; i < 400 && !resp.got; i++) {
        hop_drain_outgoing(a, forward, &to_b);
        hop_drain_outgoing(b, forward, &to_a);
        hop_poll_service_requests(b, on_request, &req);     // B (host) sees the request...
        if (req.got && !req.answered) {                     // ...and seals a response back to its caller
            req.answered = 1;
            const char *reply = "72F sunny";
            hop_send_service_response(b, req.from, req.req_id, 200, (const uint8_t *)reply, strlen(reply));
        }
        hop_poll_service_responses(a, on_response, &resp);  // A (caller) reads the reply
        now += 100; hop_node_tick(a, now); hop_node_tick(b, now);
    }
    int svc_ok = resp.got && resp.status == 200 && strcmp(resp.body, "72F sunny") == 0;
    printf("%s: hops:// service round-trip status=%u body=\"%s\"\n", svc_ok ? "PASS" : "FAIL", resp.status, resp.body);

    hop_node_free(a);
    hop_node_free(b);
    return (ok && b58_ok && svc_ok) ? 0 : 1;
}
