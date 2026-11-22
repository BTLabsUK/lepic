# Take a payment at a web shop

A shop's server can ask a buyer for one payment per order. The shop's `lepic serve` issues a
checkout request: a link and a QR code. The buyer opens it in BT Wallet, sees the shop's domain
and the amount, and approves once. No account, no pairing. The shop's server finalizes the
payment and posts it. Design: [ADR 0068](../adr/0068-invoices-the-payer-opens-need-no-pairing.md).

`docs/api/openapi.json` has every field and error in full.

## What you need

- A host that runs `lepic serve` all the time, with a wallet that receives the payments.
- A domain for the shop, served over HTTPS.
- A client certificate for your web tier, with the role `receive`: it can create requests and
  never spends.

## Set up once

1. Run serve with the owner TLS listener. The listener address is `[api] owner_tls` in
   `settings.toml`:

   ```bash
   lepic serve --socket ./w.sock --owner-tls &
   ```

2. List the web tier's certificate with the role `receive`:

   ```bash
   lepic api client add shop ./shop-cert.pem --role receive
   ```

3. Set the shop's domain, `domain` in the settings (`LEPIC_DOMAIN`, `--domain`), and restart
   serve. Serve signs this domain into every request it issues.

4. Write the domain file and publish it at `https://<domain>/.well-known/epic-wallet.json`, over
   HTTPS, with no redirect, under 4 KiB:

   ```bash
   lepic profile domain file --path ./epic-wallet.json
   ```

   The buyer's wallet fetches this file to check the request. A request without it is refused as a
   link and shown with a caution when scanned.

5. Let buyers' wallets answer straight to serve as well as through the mailbox: start serve with
   its public address, `--public-url https://pay.example.com` (repeat it for an onion address;
   or `LEPIC_SERVE_PUBLIC_URL`, comma-separated), and serve's web listener. Serve refuses a
   loopback or local-network address at startup. Without a public address, answers come
   through the mailbox slot only.

6. Send events to your backend with a webhook (`webhook_url`, `webhook_secret_file`), or read
   `GET /api/v1/events`. See "Send events to a webhook" in [recipes](../recipes.md).

## Create a request per order

Call `POST /api/v1/payments` once per order. The `id` is a UUID that your shop keeps with the
order. The same `id` returns the same payment, so a retry never makes a second request.

```json
{"id":"7b1c0f0e-5d5e-4f6a-9a53-0a2f1c9d4e11","kind":"invoice","via":"in_person",
 "amount":"12.5","message":"Order 1042","ttl_blocks":30,"finalize":"first"}
```

| Field | Meaning |
|---|---|
| `kind` | `invoice` |
| `via` | `in_person`: a code that needs no pairing |
| `amount` | Fixed by the shop. The buyer cannot change it |
| `message` | Shown to the buyer. Keep it short: a long message makes the QR code animated |
| `ttl_blocks` | How long the request stays open, in blocks. Default 30; 10 or fewer is refused |
| `finalize` | `first`: serve finalizes and posts the first valid answer. `manual` (default): answers wait in `answers` and `POST /api/v1/payments/{id}/post` finalizes the one you name |
| `direct` | Whether the code names serve's public addresses. Default: true when serve has one |

The answer's `handoff` holds the code as `text`, as `qr_frames` and as a `link`; the same `link`
is in `request.link`. Show these on the order page:

- A button "Pay with Epic Cash" whose `href` is the `link`: `epiccash://invoice/1/<code>`.
- The QR code of the `link`, for a buyer on a desktop browser. A button works only on a phone
  that has BT Wallet. Keep the QR on every checkout page.

Serve refuses to issue a request while its node is unreachable (503). Show the buyer an error
and try again.

## Follow the order

Read the payment with `GET /api/v1/payments/{id}`, or use events. The payment has a `request`
object with a `state`:

| `request.state` | Meaning | What the shop does |
|---|---|---|
| `open` | Issued, not paid, time left | Show the button and the QR |
| `paid` | An answer was finalized; serve posts it, and retries the post | Show "Payment received, waiting for confirmations" with the `reference` (four digits). Do not ship yet |
| `expired` | The time passed with no payment, or the node refused the post (a `paid` request can still end here) | Offer a new request |
| `refused` | The shop cancelled the request (`POST /api/v1/payments/{id}/cancel`) | Offer a new request, or stop |

Events: `payment.state_changed` carries the new `request.state`. When it is `paid`, wait for
`payment.confirmations_reached`: that is the signal to ship. A reorg can move a confirmed payment
back to `posted` and raises `payment.state_changed` again; hold the order until the confirmations
come back.

Serve counts each answer it refused in `request.answers_refused`, with the reason of the last
one in `request.last_refusal` (`already_finalized`, `expired`, `inputs_spent`, `bad_answer`, `cancelled`), and
keeps the request `open`. Anyone who holds the code can send an answer, so these two fields
count unchecked input: never act on them alone. The `request` object also carries `domain`,
`finalize` and `link`.

Someone who holds an order's code can make it expire: they answer first with inputs they have
already spent in a transaction still waiting in the node's pool. The answer passes the check,
serve finalizes it, the node refuses the post, and the request ends `expired`. It costs them a
fee for each code. When a request ends `expired` this way, issue a new one for the order.

Your code posts nothing and holds no keys. Mark an order paid only on your own wallet's and node's
word, never on what the buyer's browser says.

## Pay from another wallet

A buyer without BT Wallet cannot open the link. If you want to serve them, also show your wallet's
epic1 address, the amount and the order number on the page ("Pay from another wallet"), and match
the payment by hand. This path has no fixed amount and no domain check.

## What the buyer sees

BT Wallet opens the request, shows the amount, the fee, your message, your domain (checked), where
the answer goes and the time left. The buyer approves with a PIN or biometrics. The wallet then
shows "Approved. Waiting for <domain> to complete the payment." with the same four-digit reference
and can be closed.

## Limits to know

- The buyer's wallet sends the answer to your mailbox slot and, when the request names it, to your
  server's own address. The second route answers at once, so a refusal reaches the buyer in the
  same request.
- You do not learn the buyer's address. For a refund, ask for one through your own order channel.
- Someone who holds an order's code can answer first. Make a new request for the order if that
  happens, and keep codes inside the buyer's session.
- Refunds, receipts and buyer accounts are yours to build; serve sets no limits.
