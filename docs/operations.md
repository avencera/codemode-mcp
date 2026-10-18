# Operating codemode-mcp

Commands below assume the binary is on `PATH` (`~/.local/bin/codemode-mcp` after install). `cmcp` is the same
binary under a shorter name. Times in logs are UTC.

## Install

1. Build and fetch the worker in the repository: `cargo build --release`, with the Monty worker at
   `.tools/bin/monty`.
2. Write the starter config, then edit it:

   ```sh
   codemode-mcp config init            # ~/.config/codemode-mcp/config.toml; refuses to overwrite
   codemode-mcp config init --print    # or look first
   ```

   It configures 1Password, the OpenAI docs, Calendar, Reminders and Xcode. Approval notifications use the
   `[notify.ntfy]` section of `~/.config/homebased/config.toml` unless you add one here.
3. Preview, then install the LaunchAgent from the repository root:

   ```sh
   ./target/release/codemode-mcp service install --dry-run
   ./target/release/codemode-mcp service install
   ```

   This copies the binary to `~/.local/bin/codemode-mcp`, links `~/.local/bin/cmcp` to it, copies the worker to
   `~/.local/share/codemode-mcp/monty`, writes `~/Library/LaunchAgents/dev.praveen.codemode-mcp.plist` and loads
   it. Run it again after every rebuild; it replaces both files and reloads the service. If something else is
   already at `~/.local/bin/cmcp`, the install leaves it alone and logs a warning.

   Both binaries are signed with the InfraOps LLC Developer ID, the one homebased releases use, as
   `com.avencera.codemode-mcp` and `com.avencera.monty`. macOS and the 1Password app tie their approvals to an
   ad-hoc binary's hash, so without the certificate every rebuild would prompt again. The install refuses to
   run when the identity is not in the keychain. To set it up once, import the .p12:

   ```sh
   security import InfraOps.p12 -k ~/Library/Keychains/login.keychain-db -T /usr/bin/codesign
   ```

   The first signing may ask whether codesign can use the key; choose Always Allow. Check an installed binary
   with `codesign -dv ~/.local/bin/codemode-mcp`, which should show `TeamIdentifier=Q8UP8C53Y8` and `flags=0x10000(runtime)`.

4. Check it: `codemode-mcp service status` (plist, launchd state, `/healthz`).
5. Expose the approval pages to the phone: `tailscale serve --bg --https=8443 http://127.0.0.1:7681`.
   Set `public_origin` in the config to that address, such as `https://mac.tailnet-name.ts.net:8443`
   (`tailscale status --json | jq -r .Self.DNSName` prints the name). Unset, links point at
   `http://localhost:7681` and open only on the Mac. Its host is the passkeys' relying party id, so changing it
   later means enrolling them again.

## Releases

Bump `version` in `Cargo.toml`, then push a matching `v*` tag. `.github/workflows/release.yml` builds
`aarch64-apple-darwin` and installs the `monty-runtime` worker matching the `monty-pool` version in `Cargo.lock`.
It signs both with the same identity and identifiers as a local install and attaches
`codemode-mcp-<tag>-aarch64-apple-darwin.tar.gz` (holding `codemode-mcp` and `monty`), its `.sha256` and
`install.sh`. It
reads the `MACOS_SIGNING_P12_BASE64` and `MACOS_SIGNING_P12_PASSWORD` secrets and the `MACOS_SIGNING_IDENTITY`
variable, the same names homebased uses, and fails rather than ship unsigned.

## Update

```sh
codemode-mcp update --dry-run   # which release would replace what
codemode-mcp update             # latest release; --tag v0.2.0 for another
```

This downloads the release archive and checks it against the published checksum. It also requires both
executables to be signed by team `Q8UP8C53Y8` as `com.avencera.codemode-mcp` and `com.avencera.monty`. Only then
does it replace `~/.local/bin/codemode-mcp` and `~/.local/share/codemode-mcp/monty`, worker first, and restart the
service if its LaunchAgent is installed. The release signatures are kept as they are, so updating needs no
certificate in the keychain and the 1Password and EventKit grants carry over. Nothing happens when the
installed binary already reports the tag, or reports a newer version than the latest release, as a local build
can; `--force` reinstalls anyway. To roll back, pass the previous release with `--tag`. `cmd fleet update` runs
it on the Mac.

The LaunchAgent plist is not rewritten. When a release changes it, run `codemode-mcp service install` once.

## Enroll a passkey

```sh
codemode-mcp passkey enroll --label iPhone
```

- First passkey: open the printed link on the phone (10 minutes, one use) and create the passkey. The phone
  gets a notification that a first passkey is being enrolled.
- Later passkeys: the command prints a confirmation code and two links. Approve the first one with an
  existing passkey after checking that the page shows the same code, then open the second one on the new
  device. A denied or expired approval kills the enrollment link.
- `codemode-mcp passkey list` shows passkeys. `codemode-mcp passkey remove <id>` prints an approval link; the
  passkey is removed only after an existing passkey approves it. The last passkey can't be removed: enroll a
  replacement first, then remove the old one. If you lose your only device, stop the service and delete the
  row from the `passkeys` table in `~/.local/state/codemode-mcp/codemode.sqlite`.
- Every enrollment or removal request notifies the phone. One you did not start means something on the Mac
  is running the CLI: deny it and look.

## Approve at the Mac

While you are at the Mac (screen unlocked, input in the last 5 minutes), a tool call waiting for approval shows
a Touch ID prompt there instead of buzzing the phone. It names the tool, what a touch grants, the client, and
the thread title and reason the agent passed to `execute`; those two are the agent's own words, shown in quotes.

- Touch the sensor to approve the call and every tool of that server not marked `grant = "per_call"` for 60
  minutes in the agent's session. Mark writes you want asked every time, such as calendar deletes,
  `per_call`. A tool with `grant = "per_call"`, such as a
  1Password write, is approved for that one call only, and the prompt says `once`. When a script starts
  several such calls together, such as a set of deletes under `asyncio.gather`, one prompt names them all
  (`calendar.delete_event ×5 once`) and one touch approves the set. The phone push and the page cover the
  same set, and the page lists every call's arguments.
- Press **Open Page** to open the approval page in the browser, for a single call, 15 minutes, or to deny. The
  page takes your passkey.
- Leave it, and after 60 seconds the phone is told too (60 seconds after **Open Page** if you opened the page).
  Locking the screen or walking away (no input for 5 minutes) sends it to the phone within a couple of seconds.

Passkey enrollment and removal requests never offer Touch ID: they show a Mac notification and notify the
phone at once. On a Mac without Touch ID the prompt is replaced by a notification that opens the page, which
needs `terminal-notifier` (`brew install terminal-notifier`); allow its notifications the first time macOS asks.
On the phone nothing changes: the page shows everything, and you choose and confirm with the passkey.

```toml
[notify.mac]
enabled = true              # false: phone only
idle_secs = 300             # no input for this long counts as away
escalate_after_secs = 60    # then the phone is told as well
touch_id = true             # false: a notification instead of the prompt
```

## Warm up 1Password

```sh
codemode-mcp op warm
```

Runs the configured warm calls on the daemon so the 1Password app's prompts appear on the Mac now. Accept them
there; agent calls then only need the phone approval. Results are never printed.

## Give 1Password values to a program on this Mac

`codemode-mcp op read`, `op inject` and `op run` work like the 1Password CLI commands of the same names. The
difference is who approves: `op` on the gateway Mac waits for its 1Password prompt there, but these commands ask
wherever you are.

- At the gateway Mac, its own Touch ID prompt names every value and the reason the program gave, and then this
  Mac's `op` reads them. A 1Password prompt may follow while `op` is signed out.
- On the phone, Companion shows the same list. Values it holds a sealed copy of open with one Face ID, and you
  fill in the others with AutoFill or Paste.
- On a companion Mac, its own Touch ID prompt names every value, and its `op` reads them.

While you are at the gateway Mac it asks first, and the phone and companion Macs are asked 5 seconds later. While
you are away they are all asked at once. The first approval sends every value, and the other prompts are taken
down. A Deny on any device stops the request. Every prompt names the file the values go to, or the command whose
environment gets them, always in full: `op run` refuses a command line longer than 200 characters or spanning
lines (put a long script in a file), and a file path that starts or ends with a space is refused. Nothing is reused unless you ask: every command asks again, and the daemon keeps no value.
A phone keeps a copy of each value sealed to its Face ID, as for config reads.

When the next few commands need the same values, add `--keep 15m` to the first. Its prompt says the values will
be handed out again without asking for that long, at most 60 minutes, and later requests for only those
references going to the same file, or the same command's environment, are answered from memory until then.
A request going anywhere else asks again. `codemode-mcp service restart --fresh` or
`POST /admin/secrets/forget` drops them early, and a restart never carries them over.

Write a secrets file, the usual case:

```sh
cat > superalert.env.tpl <<'TEMPLATE'
PUSHOVER_USER_KEY={{ op://Personal/Pushover/user key }}
PUSHOVER_APP_TOKEN={{ op://Personal/Pushover/app token }}
TEMPLATE
codemode-mcp op inject -i superalert.env.tpl -o superalert.secrets.env --reason "freezerwatch alerts"
```

All the template's values are asked for in one approval. The file is written with mode 0600 (`--file-mode`
changes it). An existing file is replaced only with `--force`, which is checked before anyone is asked. Without
`-i` the template comes from standard input, and without `-o` the filled text goes to standard output.

For a high-severity secret that should never be in a file, keep only the references and run the command with
the values in its environment:

```sh
echo 'API_TOKEN=op://Personal/Deploy/token' > deploy.env
codemode-mcp op run --env-file deploy.env --reason "deploy" -- ./scripts/deploy lookout
```

A line's value can be a whole `op://` reference or text holding `{{ op://… }}` references, and variables already
set to an `op://` reference are read too. Any value of 3 or more characters that the command prints, and each line
of a multi-line value such as a PEM key, is replaced with `[redacted]` as the output arrives; `--no-masking` turns
that off. A program that wants to leak a value still can, for example by encoding it; masking catches accidents.
Interrupt, terminate and hang-up signals are passed to the command, and its exit code is passed back.

Read one value with `codemode-mcp op read "op://Personal/Pushover/app token"`. It prints the value, so whatever
reads the output sees it, such as an agent's context; `--out-file` writes it to a file instead. Several
references print a JSON object of each reference and its value, after one approval. A program that
does not know the item can describe it, as in `codemode-mcp op read --describe "Pushover app token"`. Only the
phone can answer a description: you pick the item there with AutoFill.

A file attached to an item, such as a signing certificate's `.p12`, is binary. Write it with
`codemode-mcp op read "op://Personal/Signing/cert.p12" --out-file cert.p12`, which keeps its exact bytes and adds no
newline; it is not printed to a terminal. Templates, env files, `write_env`, `op run` and a JSON object of several
references take text only, so they name such a reference and refuse it after the approval. Phones are never sent a
sealed copy of a binary value, so only this Mac or a companion Mac can answer one.

Every request carries `--reason`, shown quoted as the program's claim. A request holds 1 to 20 values. Only the
user that runs the daemon can make one: the CLI proves it holds the owner token in the daemon's state directory.

### Let agents write env files

The `secrets` builtin server lets an agent's script write values into an env file without ever seeing them:

```toml
[servers.secrets]
builtin = "secrets"
```

```python
await secrets_write_env(
    path="/Users/me/code/homelab/stacks/lookout/superalert.secrets.env",
    vars={"PUSHOVER_USER_KEY": "op://Personal/Pushover/user key",
          "PUSHOVER_APP_TOKEN": "op://Personal/Pushover/app token"},
    reason="freezerwatch alerts",
)
```

It is approved like `op inject`, with one prompt naming the file. The file must be an absolute path named `.env`,
`.env.<name>` or `<name>.env` in a directory that exists, and not an example or template such as `.env.example`;
a link is followed to its file. Each variable maps to one whole `op://` reference: anything else would put text
in the file that the prompt never showed, so write it yourself or use `op inject`. The lines of the variables
named are replaced, including the rest of a multi-line quoted value, new ones are added at the end, and every
other line is kept. Values that need it are single-quoted; a value with a line break or a single quote is
refused, so use `op inject` with a template for those. A new file gets mode 0600, and so does one that others could
read; one already closed to others, owned by the daemon's user and in a group other than `staff`, `everyone` or
`users` keeps its group and group bits, so a service's group can still read it; if the new file cannot be put
in that group, it gets 0600. The file is replaced by a new one, so a container that
bind-mounts the single file sees the change only after it restarts. The answer names the variables written and the device that approved,
never a value, and values of 6 or more characters are redacted from every later result; a shorter one, such
as a PIN, is not. A caller that cancels the call takes the prompts down, and nothing is written after a late
approval. `keep_minutes` works like `--keep`.

That prompt is the approval, so the gateway runs the call without asking first; a `policy = "ask"` on
`write_env` is refused at startup. The server's instructions tell agents to name a file and use this tool rather
than ask for a value.

### 1Password Environments

1Password's Environments server only works through the 1Password app on the gateway Mac. Mark it so its calls
are refused at once while you are away, instead of being approved on the phone and then waiting for a prompt
nobody can answer:

```toml
[servers.onepassword]
needs_owner_here = true
```

## Read 1Password references from another Mac

When you work from another Mac, such as a MacBook Air, the gateway Mac's 1Password prompt for `{{ op://… }}`
references cannot be answered, even over remote desktop, because Touch ID is on the gateway Mac. A companion
fixes that: the same `codemode-mcp` binary on the other Mac reads the reference through that Mac's own
1Password and `op`, after a Touch ID prompt there that names the reference, and sends the value back over iroh.
The 1Password Environments server is not covered; it only signs in through the gateway Mac's app.

1. On the gateway Mac, with the daemon running:

   ```sh
   codemode-mcp companion invite
   ```

   It first asks Touch ID on the gateway Mac ("Let a new phone or Mac pair with codemode-mcp"); approve it. It is
   refused at once while you are not at the gateway Mac, and when the prompt is denied or taken down, since the
   device that registers is trusted (see [Trusted devices](#trusted-devices)). Then it prints a command for the
   other Mac, also as a QR code, and waits until that Mac is done. The command holds
   a single-use invite that expires after ten minutes (`--valid-for <seconds>` shortens it). Until it is used,
   treat it like a password: whoever runs it first is registered, so check that the name and id `invite` prints
   are the other Mac's. Stopping `invite` with Ctrl-C does not cancel the invite; it stays valid until it is
   used or expires. Only the user that runs the daemon can open an invite: it takes the token in `admin.token`
   in the daemon's state directory (mode 0600), which other accounts on the Mac cannot read. The token is
   never sent; the CLI and the daemon each prove they hold it, so a program that took the admin port while the
   daemon was down can neither learn it nor hand out its own ticket. Once a Mac has used it, it is spent even if that Mac's setup then fails; run `invite` again,
   and the Mac keeps its existing entry.
2. Paste the command into a terminal on the other Mac. To get it there, scan the QR code with a phone's camera,
   copy the text it shows, and paste it on the Mac through Universal Clipboard. The command installs the signed
   release through `install.sh`. A release install needs no InfraOps .p12: since 0.2.1 the install keeps the
   release's own signatures. Then it runs `codemode-mcp companion pair`, which:
   - registers the Mac with the gateway over iroh. The gateway appends a `[[secrets.companions]]` entry to the
     end of its config. The running daemon starts reading through it once the check below reaches it, with
     no restart, so a Mac whose setup fails is never asked in place of the gateway's own `op`; `invite` then
     says so and exits with an error.
   - writes a `[companion]` section to this Mac's config.
   - installs and starts the companion's LaunchAgent, as `codemode-mcp companion install` does.
   - asks the gateway to read one of those references through this Mac. Approve the companion's Touch ID prompt,
     which names the reference; while `op` on that Mac is signed out, 1Password asks too. Both Macs print the value's
     length, never the value.

   On a Mac that already has codemode-mcp, the second command `invite` prints, `codemode-mcp companion pair
   <ticket>`, does the same without reinstalling. Run it with the installed binary
   (`~/.local/bin/codemode-mcp`), so the key it creates belongs to the signed copy.
3. Check it again later from the gateway Mac; approve the Touch ID prompt on the other Mac:

   ```sh
   codemode-mcp companion check op://Dev/Context7/credential
   ```

   It asks every companion and phone at once, waits for each, and prints each one's answer and the value's length,
   never the value. A device you do not touch keeps its prompt up until the 120-second limit, so to test one,
   name it, and nothing else is asked:

   ```sh
   codemode-mcp companion check op://Dev/Context7/credential --companion mba
   ```

   `--companion` takes a name from `[[secrets.companions]]` or `[[secrets.phones]]` and returns as soon as that
   device answers. An unknown name is refused with the list of configured ones. A daemon that predates
   `--companion` refuses it too, asking nobody, until `codemode-mcp service restart` runs the new binary.

If the other Mac cannot reach the gateway, pair by hand. `codemode-mcp companion invite --manual` prints a ticket
holding the gateway's id and references. `codemode-mcp companion pair <ticket>` on the other Mac writes its
`[companion]` section, starts the agent and prints a `[[secrets.companions]]` block. Append that block to the end
of the gateway Mac's config, then run `codemode-mcp companion trust <name>` there, which asks Touch ID and starts
using the Mac without a restart. The block is printed before the
agent is installed; if the install fails, fix the cause and run the same `pair` command again, which installs
again and prints the block again.

A companion built from a checkout instead of a release is signed by `companion install`, which needs the InfraOps
signing identity as in [Install](#install).

Creating items through a companion. An agent on the gateway Mac sometimes needs to save a new secret, and
`op item create` there would show 1Password's approval prompt on a screen nobody is at. Instead, the gateway can ask
a companion Mac to create the item. Creating is off until you opt in: list the vaults the companion may create items
in under `[companion]` in its config (the default is empty), then run `codemode-mcp companion install` again to
restart it:

```toml
[companion]
create_vaults = ["Personal"]
```

Then, on the gateway Mac, pipe the secret in:

```sh
pbpaste | codemode-mcp companion create --vault Personal --title "Zoho MCP infraops"
```

Options: `--category` (default `API_CREDENTIAL`), `--field` (the label of the field that holds the secret, default
`credential`) and `--companion <name>`, which is needed only when several companions are listed. The secret is read
from stdin, minus one trailing newline. Empty input is refused, and so is a value over 32 KiB once escaped for JSON
(quotes, backslashes and control characters count double or more); the command stops reading stdin past that. The command waits for the Touch ID answer on the
companion Mac (up to two minutes) and prints the new item's id and its `op://vault/title/field` reference, never the
value. Every create asks Touch ID on the companion, naming the vault first, as in `create in Personal: "Zoho MCP infraops"`,
and no approval is reused. Details:

- A companion only creates. There is no request to edit or delete an item, and a create is refused when the vault
  already holds an item with that title (compared without regard to case), so an existing secret is never
  overwritten.
- The vault, title and field label must be ASCII letters, digits, spaces, `-`, `_` or `.` (no leading `-`, no leading or
  trailing space) and are refused before any prompt otherwise, so the returned `op://` reference is always valid and
  cannot address another item (`?` and `$` mean something to `op`); rename the item in 1Password afterwards if you
  want more. The duplicate check includes archived items.
- If the command times out or loses the connection after the request went out, or `op` on the companion is killed,
  loses its answer or answers without an item id once it has the item, it says the item may have been created.
  Check the vault before trying again: once Touch ID approved, the companion finishes the create even if the gateway
  hung up.
- The command says why nothing was created: the vault is not in `create_vaults`, the title already exists, Touch ID
  was not approved, `op` failed, or the companion is too old to create items (update codemode-mcp on that Mac).
- The companion runs `op item list --vault <vault> --include-archive --format json` to look for the title, then
  `op item create --vault <vault> --format json -` with the item as a JSON template on stdin. The value is in neither
  `op`'s arguments nor its environment, and no file holds it. Only the new item's id is taken from `op`'s answer, and
  an error line from `op` is shown with the value removed.

How reads work with a companion configured:

- The gateway runs its own `op read` only while you are at the gateway Mac (input within `notify.mac.idle_secs`),
  and asks every companion at the same time. The first value wins and the other reads are cancelled, so working
  over remote desktop, which makes the gateway Mac look in use, still reaches the companion.
- A companion answers only the gateway it was paired with, and every read waits for your fingerprint on its own
  Touch ID prompt, which names the reference. While `op` on that Mac is signed out, 1Password asks too. Its
  prompt names no item and one approval lets `op` read anything for about ten minutes, so it never replaces the
  companion's own.
- The gateway accepts nothing over iroh unless a peer is listed and trusted, or an invite is open. While an invite
  is open it accepts pairing; while a trusted phone is listed under `[[secrets.phones]]` it accepts that phone's
  id, and refuses every other id. The rest of the time it only dials its companions. An invite lets one Mac register, once. Pairing the same Mac again
  keeps its existing entry, and a different Mac with a name that is already taken is listed as `name-2`.
- Each Mac's iroh key is created on first use and kept in its login keychain. The binary that creates it reads it
  without a prompt, and so does any build signed with the same identity; any other program gets a keychain
  prompt. That is why pairing and the gateway's first `invite` should run from the installed, signed binary. A
  keychain prompt asking for `dev.praveen.codemode-mcp.iroh` from any other program is worth denying.
- By default both sides use n0's relays and DNS discovery to find each other, which publishes each Mac's
  endpoint id and current addresses to n0's DNS. Traffic stays end-to-end encrypted. To keep it and the
  addresses on your network, set `discovery = false` under `[secrets]` on the gateway before inviting. The
  invite then carries the gateway's current addresses. Pairing gives the companion `discovery = false` and
  `listen = "0.0.0.0:7678"`, and lists that Mac's IPv4 addresses in its `[[secrets.companions]]` entry, so
  the two Macs must reach each other directly over IPv4, for example over the tailnet.

## Approve from an iPhone

The Companion app answers `{{ op://… }}` reads from an iPhone. The phone does not read 1Password itself: each
time a reference is read, the gateway seals the value to a key in the phone's Secure Enclave and keeps only that
sealed copy. The phone answers by opening the copy, which takes Face ID. So:

- The first time a reference is asked for, the phone has no copy. Paste the value into the read, or fill it in
  with AutoFill from 1Password or Passwords, and send it. The gateway seals whatever value wins, so the next
  read opens with Face ID. Pairing seals what the daemon has already read since its last start.
- The copy holds the value from the last time the reference was read. After rotating a secret, tap Enter a
  different value on the phone's next read, or read it once at the gateway Mac or a companion Mac and deny it
  on the phone: approving the old copy there first wins the race, and the daemon keeps that value until it
  restarts.
- Changing Face ID's enrolled faces voids the phone's key, and opening a copy then fails; pair again.

Install the app from TestFlight, or build it onto a connected iPhone with `just ios-run` (needs Xcode, xcodegen,
and the phone's UDID in `IOS_DEVICE_UDID`).

1. To wake the phone when a read comes in, give the gateway an APNs key (Certificates, IDs & Profiles, Keys,
   with Apple Push Notifications service enabled) under `[secrets]`:

   ```toml
   [secrets.apns]
   key_file = "/Users/you/.config/codemode-mcp/apns/AuthKey_ABC123DEFG.p8"
   key_id = "ABC123DEFG"
   team_id = "Q8UP8C53Y8"
   ```

   Without it, the phone answers only while Companion is open on screen. The push goes through Apple and
   names the reference and the gateway Mac, never the value. It is marked time-sensitive, so it can break
   through a Focus that allows time-sensitive notifications.
2. With the daemon running, run `codemode-mcp companion invite` on the gateway Mac and approve its Touch ID
   prompt there. Open Companion and point it at the QR code, or copy the command and tap Paste invite. The phone registers, the gateway
   appends a `[[secrets.phones]]` entry to the end of its config, and the gateway reads one reference through
   the phone: approve it with Face ID. If nothing has been read since the daemon started, there is nothing
   sealed to check yet, and pairing says so. A phone must register the iroh id it connects with, so a leaked invite
   cannot list a phone for another device's id.
3. Check it later from the gateway Mac with `codemode-mcp companion check <reference> --companion <phone name>`;
   the phone shows the read, and no other device is asked.

How reads work with a phone paired:

- Every listed phone is asked alongside the gateway's own `op` and the companion Macs, and the first value
  wins. While you are at the gateway Mac, the phones are asked 5 seconds later, so a read you answer there
  within 5 seconds never pushes to the phone. When another source answers first, the phone's prompt is taken
  down; when the phone answers first, the other prompts are.
- The phone dials the gateway, since iOS does not let a suspended app accept connections. The gateway sends
  each read over that connection and waits up to 120 seconds; the phone shows a countdown and marks the read
  expired when the gateway stops waiting.
- The phone shows one read at a time, naming the reference, and one Face ID or one entered value answers it. The
  values it opens or is given never leave its memory except in the answer, which is at most 64 KiB.
- The phone keeps its iroh key and the gateway's address in its Keychain, readable only while it is unlocked.
  Deleting the app forgets the pairing.
- With `discovery = false`, set `listen` under `[secrets]` to a fixed address such as `"0.0.0.0:7679"`, so the
  address the invite gives the phone stays valid across restarts. The phone must then reach that address
  directly, for example over the tailnet.

To unpair, tap Unpair in Companion. The gateway forgets the phone's sealed copies, push token and trust record
and stops accepting it, and the phone forgets its keys. Remove its `[[secrets.phones]]` entry from the gateway's
config by hand; until then a restarted daemon lists it as untrusted.

## Trusted devices

Any program running as your user can edit the gateway's config, so a listed companion or phone is used only with a
trust record the daemon wrote after you approved it with Touch ID at the gateway Mac: when you opened the invite it
paired with, or with `codemode-mcp companion trust <name>`. Devices listed when the daemon first set trust up, on
the upgrade to this version, were trusted then.

A listed device without a record is untrusted: the gateway never asks it, never seals a value to it, and refuses
its connections. The daemon logs a warning naming it, `/healthz` lists it under `untrusted_devices`, and
`codemode-mcp companion list` marks it:

```sh
codemode-mcp companion list
codemode-mcp companion trust mba
```

`companion trust` reads the config again, so a block appended since the daemon started is found too. It asks Touch
ID on the gateway Mac naming the device and its fingerprint, six words ("Trust the Mac “mba” (legal winner thank year
wave sausage) to answer and receive codemode-mcp secrets"); check it against the fingerprint `companion list` shows. It is refused at once while you
are not there, and when two listed devices share the name. Once approved, the daemon uses the device without a restart; a phone gets copies
of what was read since the daemon started, as at pairing. An unexpected device in the list, or a pairing or trust
prompt you did not ask for, means another program edited the config or holds the admin token; deny it and remove
the entry. If the trust key goes missing while its records remain, the daemon trusts no device until you run
`companion trust` for each again, rather than trusting whatever the config then lists.

## Calendar and Reminders access

The `calendar` and `reminders` servers read the Mac's Calendar and Reminders apps through EventKit, across every
account those apps show. The first time the daemon starts each adapter, macOS asks on the Mac whether
"codemode-mcp" may use your calendars, then your reminders; click Allow on both. Until then their tools answer
with what to do instead of data.

- The grant belongs to the signed binary (`com.avencera.codemode-mcp`), so reinstalling a rebuild keeps it. A
  binary signed with another identity, or not signed, is asked again or refused.
- Denied by mistake: turn codemode-mcp on in System Settings > Privacy & Security > Calendars (or Reminders);
  no restart is needed.
- No prompt appeared: the adapter asks again 30 seconds after an unanswered request, on the next tool call.
  `codemode-mcp service restart` asks at once.

Run by hand from a terminal (`codemode-mcp adapter calendar`), the request is attributed to the terminal app
instead, so test through the daemon.

## Xcode access

The `xcode` server runs Xcode's own bridge, `xcrun mcpbridge` (Xcode 26.3 or later), against the Xcode that
`xcode-select` picks. Xcode approves agents itself, and through the gateway the daemon is that agent for every
client. Until it is approved every tool fails with "This agent isn't approved to use Xcode's tools yet".

- Approve: have an agent call `XcodeOpenWorkspace` with a project path (or `XcodeNewProject`). Xcode asks on the
  Mac to approve the agent and that project's folder; accept both. Each new folder asks again.
- Check: `xcrun mcp-server status` shows whether Xcode's tool service is running and which workspaces are open.
  In headless mode, `sudo xcrun mcp-server approve <id>` approves a pending request by the id `status` shows.
- Revoke: `sudo xcrun mcp-server clear-permissions` removes every agent and folder grant.

## Sign in to websites from an agent

An agent that drives this Mac's screen, such as Codex with computer use, can sign in to a website with a
1Password login without the tool ever handing it the username, password or one-time password seed. The
`logins` server types the value into the field that has keyboard focus, after checking the browser, the field
and the page itself; the agent only learns which host took it. A password stays hidden behind bullets; a
username or one-time code is typed into a plain field, where the agent can see it on screen (see Limits).

1. List the logins an agent may use, and the hosts each may be typed on:

   ```toml
   [servers.logins]
   builtin = "logins"
   policy = "ask"
   tools.fill.grant = "per_call"
   tools.list.policy = "allow"

   [logins.github]
   sites = ["github.com"]
   username = "op://Personal/GitHub/username"
   password = "op://Personal/GitHub/password"
   totp = "op://Personal/GitHub/one-time password"
   ```

   `totp` is optional and names the item's one-time password field itself, without `?attribute=totp`. A
   login with it lists a `one_time_code` field; filling it types the current code, computed in the daemon from
   the seed, so the seed never reaches the agent. The code itself lands in a plain text field, where the agent
   can see it on screen until it expires.

   A site is that host only; `*.github.com` covers every host under `github.com`, but not `github.com`
   itself. Name the exact hosts the login page lives on, such as `accounts.google.com`, and use `*.` only for
   a domain whose subdomains are all its owner's: under `*.google.com`, any page on `sites.google.com` could
   take the password. The `logins` server must ask on every call; the config is refused unless `fill` is
   `ask` with `grant = "per_call"`.
2. Restart the daemon (`codemode-mcp service restart`). The first fill asks macOS to let codemode-mcp use
   Accessibility; turn it on in System Settings > Privacy & Security > Accessibility and fill again. The grant
   belongs to the signed binary, so updates keep it.

What a fill checks, from Accessibility and the browser's code signature rather than the agent's words:

- The field belongs to Safari, Safari Technology Preview, Chrome (any channel), Firefox, Microsoft Edge,
  Brave or Arc, identified by the running app's code signature, not its name. Fields in any other app are
  refused, including one an agent built to look like a browser.
- The browser cannot be scripted by other programs: a Chromium browser or Firefox started with
  `--remote-debugging-port`, `--remote-debugging-pipe` or Marionette is refused, so is Safari while
  `safaridriver` runs (a WebDriver session needs it), and so is a browser with
  Allow JavaScript from Apple Events turned on in its saved preferences. A saved "off" is not proof, since a
  browser writes a change out only seconds later, and Safari's file needs Full Disk Access to read at all, so
  the Touch ID prompt says the setting could not be confirmed off; look at the browser's Develop menu before
  you approve. Chrome, Edge, Brave and Arc keep it in each profile's `Preferences`.
- A password goes only into a password field, the kind that shows bullets. A username or a one-time code goes
  only into a one-line text field.
- The field's page must be `https` on port 443, and its host one of the login's `sites`. A field inside a
  frame is checked against the frame and every page around it, so each of those hosts must be listed. This
  relies on the browser exposing each frame's address to Accessibility; a frame it does not expose goes
  unchecked.
- Focus and the page are checked again before each character, and typing stops once either has changed. Keys
  already sent may still land, so a few characters can reach a field in the same app that took focus; keys never
  go to another app. The answer then says to clear the field and fill again.

These checks run before you are asked, so a fill into the wrong place is refused without a prompt. Each fill
is then approved like any `per_call` tool: Touch ID while you are at the Mac, otherwise a passkey on the phone.
The Touch ID prompt and the Mac's notification say what goes where, such as `password for github into
github.com in Safari`, followed by any setting that could not be checked, and the approval page shows the same
under `checked`. The phone's notification names only the tool, as for every call. After you approve, the field
is checked again and must still be on the host you approved; if the page moved to another host, even one of
the login's sites, nothing is read or typed and the agent must fill again.

The value is then read like a server secret, through `op` while you are at the Mac, or a companion Mac or phone
when you are not, and kept in the daemon's memory until it restarts. After changing a password in 1Password,
restart the daemon so the next fill reads the new one. A one-time password's seed stays valid, so its codes
keep working from the cached read.

Limits:

- Web pages only, in one of the browsers above. Native app fields have no page address and are refused.
- One-time codes from an authenticator seed (TOTP) only, typed into a single text field; a page that splits
  the code across six boxes needs it typed by hand. SMS codes and push approvals stay with you.
- A username or one-time code lands in a plain text field, so the agent sees it on screen like any typed
  text. A password shows as bullets, until something clicks the page's show-password button; then the agent
  can read it too.
- The agent never gets the value from the tool, but anything that can run script in the page could read the
  field once it is filled. The daemon refuses the switches it can see, but a browser extension or a program
  you allowed to control the browser through Apple Events still could: when macOS asks whether the agent's
  app may control Safari or Chrome, choose Don't Allow.

## OAuth sign-in

```sh
codemode-mcp oauth login <server>    # prints the link and opens the browser
codemode-mcp oauth status            # logged in, expiry, refresh token, scopes, connection state
codemode-mcp oauth logout <server>   # forget the tokens; the server reconnects anonymously
```

For a `url` server with `oauth = true`. The browser returns to `http://127.0.0.1:7682/oauth/callback/<server>` on the admin listener, so sign in from a
browser on this Mac. Tokens refresh automatically. A server that refuses anonymous clients shows
`needs_login` in `/healthz` and `codemode-mcp tools` until you sign in.

An authorization server without dynamic client registration needs a client you create there yourself: set
`client_id`, and `client_secret` for a confidential client. The secret can be an `op://` reference; it is read
at login and stored with the tokens. `authorization_params` adds query parameters to the sign-in URL.

### Gmail

Google's Gmail MCP server (developer preview) takes a client from your own Google Cloud project:

1. In a Google Cloud project, enable the Gmail API and `gmailmcp.googleapis.com`.
2. Under Google Auth Platform, set up the consent screen (audience Internal for a Workspace account; External
   needs you added as a test user).
3. Create an OAuth client of type Web application, tick "Use this client for an AI-powered agent", and add the
   redirect URI `http://127.0.0.1:7682/oauth/callback/gmail`.
4. Save the client secret in 1Password, add the tables below, restart, and run `codemode-mcp oauth login gmail`.

```toml
# every Gmail call asks on the phone; reads accept a 15 or 60 minute session
# grant, and every change asks each time. There is no send tool: drafts are
# as far as it goes
[servers.gmail]
url = "https://gmailmcp.googleapis.com/mcp/v1"
oauth = true
client_id = "<id>.apps.googleusercontent.com"
client_secret = "{{ op://Private/Google Workspace MCP/credential }}"
# without these Google issues no refresh token and the login lasts an hour
authorization_params = { access_type = "offline", prompt = "consent" }
scopes = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.compose",
  "https://www.googleapis.com/auth/gmail.modify",
  "https://www.googleapis.com/auth/gmail.labels",
]
policy = "ask"
aliases = ["email", "mail"]

[servers.gmail.tools.create_draft]
grant = "per_call"
# ...and the same for every other tool that is not a read
```

The server lists its tools without a login, so they appear in the catalog at once; calls fail until you sign
in.

Google's Calendar MCP server (`calendarmcp.googleapis.com`) refuses every tool call unless the Google Cloud
project is enrolled in the Workspace Developer Preview Program. For Google Calendar, add the account to the
Mac's Calendar app and use the `calendar` server instead (see
[Calendar and Reminders access](#calendar-and-reminders-access)).

## Add a server

Add a table under `servers` and restart (`codemode-mcp service restart`):

```toml
[servers.docs]                 # remote, Streamable HTTP
url = "https://example.com/mcp"

[servers.mytool]               # local, stdio
command = "/opt/homebrew/bin/mytool-mcp"
args = ["--stdio"]
policy = "ask"                 # every call needs a phone approval; logs keep tool names only

[servers.mytool.tools.delete_everything]
policy = "deny"
```

- `oauth = true` on a `url` server enables `oauth login` (optional `scopes`, `client_name`, or `client_id` and `client_secret` for a client registered ahead of time, and `authorization_params`).
- Rarely used stdio servers: `lazy = true` starts the process on the first call and stops it after `idle_secs` (default 600) without calls; `/healthz` shows it as `idle` meanwhile and its tools stay searchable. A failed start fails that call only, and the next call tries again.
- Keys stay in 1Password: a `headers`, `env` or `url` value can hold `{{ op://vault/item/field }}` references, as in `op inject`, e.g. `headers = { authorization = "Bearer {{ op://Dev/Context7/credential }}" }`. The daemon runs `op read` the first time the server connects and keeps the value in memory until it exits. A clean stop (`service restart`, `update`, a reboot) hands the values to the next daemon sealed, so it asks nothing again; to pick up a rotated key, run `codemode-mcp service restart --fresh`. With the 1Password app integration the Mac asks once when the daemon starts (a locked or unanswered prompt shows `secret_unavailable` in `/healthz` and retries every 10 minutes). `[secrets] op` names the `op` binary (default `op` on `PATH`). A `url` that carries the key, as Zoho's MCP URLs do, should embed the reference where the key sits: `url = "https://<server>-<id>.zohomcp.com/mcp/{{ op://Personal/Zoho MCP - InfraOps/key }}/message"`. References in a `url` may sit only in path segments and query names or values, never in the scheme, credentials, host, port or fragment, and the `url` needs a literal host; anything else is refused when the config loads. A key embedded in a `url` may hold only ASCII letters, digits and `- . _ ~ + / = : @ ! * , ;` (at least 16 bytes), which covers hex, base64, base64url, JWT-like and colon-separated keys; any other character, such as `\`, quotes, `<`, `>`, `^`, `{`, `}`, `|`, `[`, `]`, `#`, `?`, `%`, `&`, `$`, `(`, `)` or a space, refuses the server with a configuration error. It is encoded as data where it sits, so `/` or `+` in a key stays part of that one segment or query value. The secrets are exactly the values 1Password returns, in the encodings libraries print them in (percent-encoded in either case, JSON-escaped, HTML character references such as `&#43;` or `&plus;`, `+` read as a space), matched ignoring ASCII case, and any run of 8 or more of its bytes is redacted too, since rmcp cuts invalid responses to 256 bytes and can leave only part of a key; nothing else in the URL is guessed to be a key. A `url` that is one whole reference (`url = "{{ op://Personal/Zoho MCP infraops/credential }}"`) is refused when the config loads, with or without OAuth, because codemode cannot tell which part of such a URL is the key; embed the reference instead, e.g. `url = "https://host/mcp/{{ op://Vault/Item/key }}"`. Log text is matched through nested escape layers (a client's `Debug` output escapes the JSON escapes of a response body), up to 4 passes. Only the configured template is ever shown (companion prompts name the reference, never the value), and the resolved URL is redacted from errors, `/healthz` and the daemon's logs. Whatever OAuth would store (credentials, pending state, the client registration) or print (the authorization link) is refused when it holds a key, and the link's `resource` parameter is left out only when it holds the key.
- Per tool: `policy` (`allow`, `ask`, `deny`) and, for `ask`, `grant` (`session` or `per_call`). A `session` grant is given to the calling client, not to one MCP session: it covers every running session of that client name for 15 or 60 minutes.
- The server is session-less: it issues no `mcp-session-id`, for any protocol version. Clients are told apart by the client name in the request `_meta`, the `initialize` handshake or the `user-agent` header. While `execute` or `wait` is waiting, it sends progress notifications every `limits.progress_interval_ms` (15000) to clients that sent a `progressToken`.
- Result types. A tool that declares no output schema returns a `JsonValue` that scripts read with the `json_*` accessors. Give it a type in the tool's table: `output = "text"` for prose or markdown (the script gets a `str`, never parsed), or `output_schema` with an inline JSON Schema table for JSON, e.g. `output_schema = { type = "object", required = ["id"], properties = { id = { type = "string" } } }`. An upstream-declared schema wins over `output_schema` unless the table also sets `force_output_schema = true`. Every result is checked against the schema, so write only fields the tool really returns and mark optional ones with a `required` list or a `["string", "null"]` type. Probe it first: `codemode-mcp exec` a script that prints `json.dumps(await server_tool(...))`.
- Check the result with `codemode-mcp tools` (connects, lists every tool with its status).

### Keep servers in a shared file

To keep the servers in a file you can share, such as one in a public dotfiles repository, list it in `include`
at the top of `config.toml`, before any table. The values only this Mac should have, such as `public_origin`,
`[secrets]` peers and personal `env` values, stay in `config.toml`:

```toml
include = ["~/code/dotfiles/config/codemode-mcp/servers.toml"]
public_origin = "https://mac.example.ts.net"

[servers.gmail.env]            # added to the shared server's env
USER_GOOGLE_EMAIL = "you@example.com"
```

- Paths start with `~/` or are relative to the directory `config.toml` sits in. When `config.toml` is a symlink,
  that is the link's directory, not its target's.
- An included file may hold only `[servers]`, and cannot include others. A file kept somewhere shared cannot add
  a companion, a phone, a `[companion]` section or any other setting. Its servers still run commands on this Mac,
  so include only files you control.
- Tables merge key by key, so `config.toml` can add keys to a server the shared file defines. A value set in both
  files refuses the config and names both files.
- Pairing and invites still append to `config.toml`, never to an included file.
- Included files are read when the config loads, so restart after editing one.

## Restarts and in-flight work

`service install`, `service restart`, a crash and a reboot all restart the daemon. State is in
`<state_dir>/codemode.sqlite` (default `~/.local/state/codemode-mcp/`) and needs no import: the daemon opens the
file the previous build wrote, in place, and adds its new tables on first start. There is no
`codemode.sqlite.imported-*` file and the old file is not moved or copied, so back it up before installing if you
want a way back (a build older than the schema refuses to open it).

What a restart does:

- The values the daemon read from 1Password for its servers carry over a clean stop. The stopping daemon seals
  them with AES-256-GCM under a new random key, writes the ciphertext to `<state_dir>/secrets.handoff` (mode
  0600) and keeps the key in the login keychain, where only the installed, signed binary reads it without a
  prompt. The next daemon opens both once and deletes both, and ignores a handoff more than 10 minutes old. A
  crash leaves nothing, so that daemon asks once. `service restart --fresh` drops the values first, so the next
  daemon reads each again, as after rotating a key. A daemon run from anything but the installed binary, or
  with `secrets.identity_file` set, keeps the key in `<state_dir>/secrets.handoff.key` instead. Values a program
  asked for with `codemode-mcp op` are never kept or handed over.
- A config value goes only to a server you approved it for, as that server stands. A server that is new, or
  whose `command`, `args`, `cwd`, `env`, `url`, `headers`, `client_id` or `client_secret` changed, is asked for
  once, cached value or not, restart or crash; changing a policy or tool setting asks nothing. At the gateway
  Mac a Touch ID prompt names the server first ("Give op://… to the server “name”, new or changed since it was
  last approved"), even while 1Password would answer without one; the phone and companion Macs ask as for any
  read. A Deny keeps it unapproved. The approvals sit in `<state_dir>/secrets.approved`, each signed with a key
  derived from the device trust key. Upgrading approves every server the config lists at that moment.
- Finished results stay available to `wait` for 30 minutes (`limits.result_ttl_secs`).
- Pending approvals stay pending; the phone link keeps working and the timer continues from the original
  deadline. An ntfy that had failed is sent again at boot.
- Executions waiting only on an approval resume once it is approved, denied or expired. Calls they make after
  that use the tools the restarted daemon has.
- On a normal stop (SIGTERM, which `service restart` sends) the daemon stops taking new executions, waits up to
  `limits.drain_secs` (default 20) for running scripts, parks the ones waiting on approval, and flushes the usage
  log. The plist `ExitTimeOut` is set to the drain plus 30 seconds when you run `service install`, so rerun it
  after changing `drain_secs`; `serve` logs a warning at start when the installed plist allows less than the
  drain plus 10 seconds.
- A script still running after the drain, or running when the daemon died, ends as `interrupted`. `wait` says so
  and lists the upstream calls that finished. Writes may have happened: check before running it again.
- Anything that touched a sensitive server (1Password) is not written to disk. After a restart `wait` reports it
  as `interrupted`, its approval page shows the request as withdrawn, and the script has to be run again. Grants
  survive.
- Enrollment links and passkey removals waiting on approval survive too.
- Only one daemon can run on a state directory: a second `codemode-mcp serve` exits at once with "another
  daemon owns <dir>" and changes nothing. A CLI command (`exec`, `stats`, `review`, `passkey list`) works beside
  the running daemon.
- A kill with SIGKILL, or a power loss, also drops the last usage-log lines that were not yet flushed.

## Read the usage review

```sh
codemode-mcp stats --since 7d
codemode-mcp review --since 7d --out review.md
```

The review lists the most common error fingerprints with an example, the runs that struggled most (a run is an MCP session, or for session-less clients one client's calls with gaps under 10 minutes, so approximate),
hallucinated tool names, scripts that called tools they never described, type strictness, and approval timings.
Use it to fix the agent directions or the stubs. `/stats` on the main listener shows the same numbers as `stats`.

The "Type strictness" section ends with a verdict line:

- `Looks too loose` names the signal: probe executes, runtime errors typing should have caught, or scripts
  parsing JSON text. Look at the untyped-tool ranking in the section and add `output` / `output_schema` overrides for the
  top tools.
- `Looks too strict` names a rule whose errors the next execute did not fix, runs abandoned after a type error, or
  a tool whose results keep failing their schema (`output_mismatch`: loosen or fix that `output_schema`, or use
  `output = "text"`).
- `Mixed` means both; fix the schema mismatches first, since they hide the rest.
- Act on a signal that holds across two reviews; the thresholds are in `docs/design.md`.

## Troubleshoot

- Logs: `~/.local/state/codemode-mcp/logs/codemode-mcp.err.log` (set `RUST_LOG=debug` in the plist's
  environment for more).
- `service status` says not loaded: `service install` again; `launchctl print gui/$(id -u)/dev.praveen.codemode-mcp`
  shows launchd's view.
- An upstream is `unavailable`: `codemode-mcp tools` prints the local error. For stdio servers check the command
  path; launchd's PATH is `~/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin`.
- `ask` calls are refused at once: no notifier (add `[notify.ntfy]`) or no passkey (enroll one).
- An approval link does not open on the phone: check `tailscale serve status` and `public_origin`.
- Requests go to the phone while you are at the Mac: the log says why (`Touch ID is not available`,
  `Mac notification failed`). The daemon must run as a LaunchAgent in your login session to see the screen.
- Monty worker not found: `service install` again, or set `worker_path`.
- A calendar or reminders tool says macOS denied access, or is asking: see Calendar and Reminders access.
- An Xcode tool says the agent isn't approved: see Xcode access.

## Uninstall

```sh
codemode-mcp service uninstall --dry-run
codemode-mcp service uninstall
```

This unloads the service and removes the plist. State (`~/.local/state/codemode-mcp`), the config and the
installed binary, the `cmcp` link and the worker stay; delete them by hand if wanted. Remove the agents' `codemode` MCP entries and
`tailscale serve --https=8443 off` as well.
