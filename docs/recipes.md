# LEPIC recipes

Interactive version: [docs.btlabs.uk/developers/lepic/recipes](https://docs.btlabs.uk/developers/lepic/recipes/).

Each recipe shows the `lepic` command first, then the same task through the
[wallet API](api/README.md). The API side assumes `lepic serve --socket ./w.sock` is running for
the wallet. The CLI names a transaction by its local id (`TX_ID`, as `lepic tx list` shows it);
the API names a payment by its slate id (`SLATE_ID`).

## Set up

### Create a wallet

CLI:

```bash
# Prints the recovery phrase once and asks for a new password
lepic wallet init
# 12 words instead of 24
lepic wallet init --words 12
```

### Show your address

CLI:

```bash
# The epicbox address to give to someone who pays you
lepic wallet address
# The same as a QR code in the terminal
lepic wallet address --qr
```

API:

```bash
# The Epicbox address and one epic1 address per account
curl --unix-socket ./w.sock http://lepic/api/v1/addresses
```

### Check the balance

CLI:

```bash
# Refreshes from the node, then prints height and balances
lepic wallet info
```

API:

```bash
# Accounts with spendable, confirming, pending, maturing, locked and total
curl --unix-socket ./w.sock http://lepic/api/v1/accounts
```

### Back up the wallet

```bash
# Copies the vault and the database to the new folder DIR, also while serve runs
lepic wallet backup ./wallet-backup
```

The API has no call for it: the command runs in its own process. The copy stays encrypted under the wallet password. Keep the recovery phrase too: it is the only
way back if the data directory is lost. Run one live instance per recovery phrase; two installs
on one phrase without a link are unsupported.

A backup is a snapshot. Restore it only when the original is gone for good, run
`lepic wallet scan` before sending or receiving, and check payments that were open at the backup
and created after it against your own records before you retry any: [Backup](cli.md#wallet). Copy
the data directory before the first start of a new `lepic` release: the upgrade keeps no copy and
the old release refuses the upgraded wallet.

## Get paid

### Listen for payments

CLI:

```bash
# Stays connected to the epicbox relay and receives what is sent to your address
lepic epicbox listen
```

API:

```bash
# Serve listens by itself; listeners.epicbox.state says whether it is connected
curl --unix-socket ./w.sock http://lepic/api/v1/status
```

### Receive a payment by file

CLI:

```bash
# Writes the reply to reply.json; give that file back to the sender
lepic tx receive payment.json --reply-file reply.json
```

API:

```bash
# outcome is "received"; handoff.text is the answer to give back
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d "{\"file_base64\":\"$(base64 -w0 payment.json)\"}" \
  http://lepic/api/v1/open
```

### See what came in

CLI:

```bash
# Refresh first, then list the transactions
lepic tx list --refresh
```

API:

```bash
# Incoming payments that are on the chain, newest first
curl --unix-socket ./w.sock \
  'http://lepic/api/v1/payments?direction=in&state=confirmed'
```

`state=confirmed` means the chain holds the payment with at least one
confirmation. Do not credit a customer on that. Each payment carries
`confirmations`, and `final` turns true once they reach the
`final_confirmations` setting (6 unless set, 1 to 1440). The wallet raises
the `payment.confirmations_reached` event at that point. Credit on `final`
or on that event. A reorg can still take a `confirmed` payment off the chain for the next 1,440
blocks: serve then moves it back and raises `payment.state_changed`, so keep watching for that.

## Pay

### Pay an address

CLI:

```bash
lepic tx send --to ADDRESS@HOST AMOUNT --message 'rent'
```

API:

```bash
# Choose the id yourself, so a repeat of the call cannot pay twice
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"id":"SLATE_ID","to":"ADDRESS@HOST","amount":"AMOUNT","message":"rent"}' \
  http://lepic/api/v1/payments
```

Serve finishes and posts the payment when the other wallet answers.

### Check the fee before paying

API:

```bash
# Answers fee, max_amount and outputs; changes nothing
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"to":"ADDRESS@HOST","amount":"AMOUNT"}' \
  http://lepic/api/v1/payments/estimate
```

### Pay by file

CLI:

```bash
# 1. Write the payment to a file and give it to the receiver
lepic tx send --to-file payment.json AMOUNT
# 2. Finalize the reply they give back; this posts the transaction
lepic tx finalize reply.json
```

API:

```bash
# 1. handoff.text and handoff.file_name are what to give the receiver
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"id":"SLATE_ID","via":"file","amount":"AMOUNT"}' \
  http://lepic/api/v1/payments
# 2. Open the reply; outcome is "finished" and the payment is posted
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d "{\"file_base64\":\"$(base64 -w0 reply.json)\"}" \
  http://lepic/api/v1/open
```

### Pay a contact

CLI:

```bash
lepic tx send --to-contact CONTACT_ID AMOUNT
```

API:

```bash
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"id":"SLATE_ID","to":"contact:CONTACT_ID","amount":"AMOUNT"}' \
  http://lepic/api/v1/payments
```

## Invoices

### Ask for an amount by file

CLI:

```bash
# Give invoice.json to the payer; finalize the reply they give back
lepic invoice issue --to-file invoice.json AMOUNT
lepic tx finalize reply.json
```

API:

```bash
# handoff.text is the invoice to give the payer
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"id":"SLATE_ID","kind":"invoice","via":"file","amount":"AMOUNT"}' \
  http://lepic/api/v1/payments
# Open the payer's answer; outcome is "finished"
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d "{\"file_base64\":\"$(base64 -w0 reply.json)\"}" \
  http://lepic/api/v1/open
```

### Pay an invoice

CLI:

```bash
# Type the amount the invoice asks for; the reply goes to reply.json
lepic invoice pay invoice.json AMOUNT --reply-file reply.json
```

API:

```bash
# 1. Hold it: outcome is "invoice_parked", the payment is in needs_approval
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d "{\"file_base64\":\"$(base64 -w0 invoice.json)\"}" \
  http://lepic/api/v1/open
# 2. Pay it, typing the amount again
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"amount":"AMOUNT"}' http://lepic/api/v1/payments/SLATE_ID/approve
```

A different amount is refused and the invoice stays held.

### Decline an invoice

CLI:

```bash
lepic contact decline SLATE_ID
```

API:

```bash
curl --unix-socket ./w.sock -X POST http://lepic/api/v1/payments/SLATE_ID/decline
```

### Invoice a contact

CLI:

```bash
lepic contact invoice CONTACT_ID AMOUNT --reference 'March rent'
```

API:

```bash
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"id":"SLATE_ID","kind":"invoice","to":"contact:CONTACT_ID","amount":"AMOUNT"}' \
  http://lepic/api/v1/payments
```

### Let a contact send you invoices

CLI:

```bash
lepic contact allow-invoices CONTACT_ID on
```

API:

```bash
curl --unix-socket ./w.sock -X PATCH -H 'content-type: application/json' \
  -d '{"allow_invoices":true}' http://lepic/api/v1/contacts/CONTACT_ID
```

### Pay a contact's invoice

CLI:

```bash
# Fetch new invoices, then pay one with the amount it asks for
lepic contact collect
lepic contact pay-invoice SLATE_ID AMOUNT
```

API:

```bash
# Invoices from contacts wait in needs_approval
curl --unix-socket ./w.sock \
  'http://lepic/api/v1/payments?state=needs_approval&contact_id=CONTACT_ID'
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"amount":"AMOUNT"}' http://lepic/api/v1/payments/SLATE_ID/approve
```

## Contacts

### Invite someone

CLI:

```bash
# Prints the invite link to give the other person
lepic contact invite --name 'Shop' --expiry 24h --qr
```

API:

```bash
# pairing.invite_link in the answer is the link to give
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"method":"invite","label":"Shop","expires_in":"24h"}' \
  http://lepic/api/v1/contacts
```

### Accept an invite

CLI:

```bash
lepic contact accept INVITE_LINK --name 'Alex'
```

API:

```bash
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"method":"accept","invite":"INVITE_LINK","label":"Alex"}' \
  http://lepic/api/v1/contacts
```

### Compare the four words

CLI:

```bash
# Both screens show the same four words: record the match
lepic contact sas CONTACT_ID match
```

API:

```bash
# verify_words on the contact are the four words
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"result":"match"}' http://lepic/api/v1/contacts/CONTACT_ID/verify
```

## In person and links

### Ask for a payment in person

CLI:

```bash
# 1. Show the code; the payer scans it once
lepic in-person invoice AMOUNT
# 2. Online, fetch the answers; offline, take the one the payer shows back
lepic contact collect
lepic in-person take ANSWER
# 3. Finalize the answer whose check code both screens show
lepic in-person answers SLATE_ID
lepic in-person finalize SLATE_ID 1
```

### Pay a code in person

CLI:

```bash
# See what the scanned code asks before paying
lepic in-person read --hex HEX
lepic in-person pay --hex HEX AMOUNT
# Post the printed answer to the relay the code names
lepic in-person post SLATE_ID
```

Offline, show the printed answer to the other screen instead of posting it.

### Make an epic1 link

CLI:

```bash
lepic epic1 link AMOUNT --message 'Order 42' --qr
```

API:

```bash
# text in the answer is the epic: link to show or print
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"amount":"AMOUNT","message":"Order 42"}' http://lepic/api/v1/links
```

### Pay a link

CLI:

```bash
# Show what the link asks, then pay it
lepic epic1 read LINK
lepic epic1 pay LINK
# Fetch the answer and finalize the payment
lepic contact collect
```

API:

```bash
# The amount can be left out when the link names one
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"id":"SLATE_ID","to":"LINK"}' http://lepic/api/v1/payments
```

### Check a file or code before acting on it

CLI:

```bash
lepic epictx open payment.epictx
```

API:

```bash
# Says what the text is and what opening it would do; stores nothing
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"text":"TEXT"}' http://lepic/api/v1/inspect
```

## Run as a service

### Start serve

CLI:

```bash
# The password comes from the file LEPIC_PASSWORD_FILE names
lepic serve --socket ./w.sock &
```

API:

```bash
curl --unix-socket ./w.sock http://lepic/api/v1/status
```

### Add an owner TLS client

CLI:

```bash
# settings.toml holds the listener: [api] owner_tls = "IP:PORT"
lepic serve --socket ./w.sock --owner-tls &
# List the client's certificate with its role: read, receive or full
lepic api client add till ./till-cert.pem --role receive
lepic api client list
```

The client trusts `api-tls.pem` from the data directory and presents its own certificate with an
Ed25519 key.

### Send events to a webhook

API:

```bash
# config.toml: webhook_url = "https://shop.example/hooks/lepic"
#              webhook_secret_file = "/srv/lepic/webhook.secret"
# Restart serve, then check the webhook's state and cursor
curl --unix-socket ./w.sock http://lepic/api/v1/webhook
# Send again from an event id after the receiver was down
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"after":41}' http://lepic/api/v1/webhook/resume
```

### Read events

API:

```bash
# A page of payment events after id 0
curl --unix-socket ./w.sock 'http://lepic/api/v1/events?after=0&types=payment.*'
# A live stream that resumes after the last id seen
curl -N -H 'Accept: text/event-stream' -H 'Last-Event-ID: 42' \
  --unix-socket ./w.sock http://lepic/api/v1/events
```

## Fix and restore

### Look at a transaction

CLI:

```bash
lepic tx show TX_ID --refresh
```

API:

```bash
# state, actions, delivery.state and confirmations
curl --unix-socket ./w.sock http://lepic/api/v1/payments/SLATE_ID
```

### Cancel a payment

CLI:

```bash
# Frees the coins of a transaction that is not posted
lepic tx cancel TX_ID
```

API:

```bash
# Allowed when the payment's actions list cancel
curl --unix-socket ./w.sock -X POST http://lepic/api/v1/payments/SLATE_ID/cancel
```

### Post a transaction again

CLI:

```bash
lepic tx post TX_ID --fluff
```

API:

```bash
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"fluff":true}' http://lepic/api/v1/payments/SLATE_ID/post
```

### Rescan the chain

CLI:

```bash
lepic wallet scan --start-height 2000000
```

API:

```bash
# Answers 202; wallet.progress events report the scan
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"from_height":2000000}' http://lepic/api/v1/wallet/scan
```

### Restore a wallet from its words

CLI:

```bash
# Asks for the recovery phrase and a new password, then scans the chain
lepic wallet restore
# Start the scan at a height; outputs below it are not found
lepic wallet restore --from-height 2000000
```
