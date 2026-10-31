# EeroNotifier

Sends a [Pushover](https://pushover.net) notification when a watched phone arrives home or leaves, based on an eero mesh network plus live probes on the local network.

It runs from cron once a minute on a Linux box that is on the same LAN as the phones.

## How presence is decided

The model is **"LAN establishes, eero sustains"**:

- **Arrive:** a device is marked HOME only after it answers live LAN probes (arping, TCP to the iOS lockdown port 62078, ping, IPv6 ping). Every reply is checked against the device's MAC address. It needs `consec_to_arrive` hits within the last `arrive_window` runs. eero's `connected` flag alone can never make a device arrive, because eero reports phantom associations for devices that aren't there.
- **Stay:** iPhones put Wi-Fi to sleep and stop answering probes for a while. During those gaps, eero saying `connected=True` keeps a device HOME, but only for `eero_sustain_max_min` minutes after its last LAN reply.
- **Leave:** a device is marked LEFT after `leave_minutes` with neither a LAN reply nor a valid eero sustain.

eero also supplies discovery data: the current IPs, the rotating private MAC addresses and the IPv6 link-local addresses to probe. Devices are matched by their eero name first, which survives iOS MAC rotation, and by MAC address second.

Some phones sleep much harder than others and go quiet on the LAN for 20 minutes while still home. A device can override the sustain window in its own entry, with `eero_sustain_max_min: 20`. When a phone really leaves, eero flips to `connected=False` within a few minutes, so a longer window barely delays real departure alerts.

All state lives in `watch.state.json`: the current per-device state, recent run history and a bounded log of transitions.

## Setup

**Requirements:** Linux, Python 3.12+, `arping` (iputils), `ping`/`ping6`, `ip`, a Pushover account and an eero account.

```bash
python3 -m venv venv
```

```bash
venv/bin/pip install requests rich pyyaml
```

`arping` needs raw-socket permission to run without root:

```bash
sudo setcap cap_net_raw=ep $(which arping)
```

### 1. Config

```bash
cp config.example.yaml config.yaml
```

Fill in the following:

- `network`: your eero network name
- `pushover.token` and `pushover.user`
- `watched`: the devices to track

`config.yaml` is gitignored because it holds your credentials and device MAC addresses. It's the only file that differs between deployments: `watch.py`, `utils.py` and `config.py` are meant to stay identical on every box. Run one instance per physical network, since LAN probes only reach the local subnet.

### 2. eero session cookie

```bash
./generate_cookie.sh
```

The script asks for the email or phone number on your eero account. eero sends a one-time code there, and the script saves the session token to `session.cookie`. A failed login leaves the existing cookie untouched. To test the current cookie:

```bash
./generate_cookie.sh --check
```

### 3. Run it

Run it once by hand to see the status table:

```bash
venv/bin/python watch.py
```

Then add it to cron, which runs every minute. `run_watch.sh` uses `flock` so runs never overlap:

```
* * * * * /path/to/EeroNotifier/run_watch.sh >> /path/to/EeroNotifier/watch.cron.log 2>&1
```

To rotate the log, install `log_rotate.config` into `/etc/logrotate.d/` after editing its paths. Use `./log.sh` to follow the log live.

Set `WATCH_DEBUG=1` to print per-network fetch diagnostics. `WATCH_WIDTH` sets the table width when running without a TTY.

## Files

| File | Purpose |
|---|---|
| `watch.py` | Main script: eero fetch, LAN probing, state machine, notifications, status table |
| `utils.py` | Time helpers, MAC normalization, cookie storage, Pushover, LAN probes |
| `config.py` | Loads `config.yaml` with dotted-path lookup |
| `config.example.yaml` | Template for `config.yaml` |
| `eero/` | eero cloud API client (see Credits) |
| `generate_cookie.sh` | Log in to eero and write `session.cookie` |
| `run_watch.sh` | Cron entry point (flock-wrapped) |
| `diag_probe.sh` | Temporary probe diagnostic; reads its target from `config.yaml` → `diag_probe` |
| `gitPushUpdate.sh` | Commit, tag and push helper |

## Credits

The eero API client in `eero/` is based on [343max/eero-client](https://github.com/343max/eero-client), vendored here with small local additions (e.g. `Eero.device()`).
