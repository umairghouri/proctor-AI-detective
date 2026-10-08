# Proctor AI Detective

A small Windows desktop app that answers one question:

> **Is Parakeet AI — or another screen-capture-evading AI assistant — running on this machine right now?**

It is a single ~1 MB `.exe`. Nothing to install, no runtime download, no service, no driver,
no network callback. You run it, it scans for a few seconds, and it shows you the evidence it
found and the reasoning it applied to that evidence.

---

## Read this before you read anything else

**What this tool cannot do.** This matters more than the feature list, so it goes first.

* **One device.** It inspects *this* Windows machine. The single most common way people use a
  tool like Parakeet AI is on a **second device** — a phone propped behind the laptop, a tablet,
  a second PC. Proctor AI Detective cannot see any of that. It is not a camera. It is not a proctor.
* **One user session.** It sees processes and windows in the session it runs in. Another signed-in
  user's session, a different desktop, a virtual machine, or a remote session is out of reach.
* **One moment.** A scan is a snapshot. Software started after the scan, or closed before it,
  does not appear. A clean result at 10:00 says nothing about 10:05.
* **A clean result is not proof of absence.** It is the absence of proof. Those are different
  claims and this tool only ever makes the second one. Every "Clear" verdict in the report says so
  in words, not just in a colour.
* **It is evadable, and the evasion is not hard.** The "Known limitations and how to evade this
  tool" section below is deliberately specific. A detection tool that hides its own weaknesses is
  worse than useless to anyone who has to decide whether to trust its output.

**What it does do well.** It finds a specific, narrow, hard-to-fake behaviour — a program telling
Windows "exclude my window from screen capture" — and it tells you who that program is, with the
evidence attached, instead of just flashing a red light.

---

## Build

Requires the .NET SDK (any version 6.0 or newer) to **build**. The built app requires nothing but
Windows.

```powershell
cd D:\proctor-AI-detective
.\build.ps1
```

This cleans, restores, builds `src\ProctorAIDetective\ProctorAIDetective.csproj`, stages `dist\`, and produces
`dist\ProctorAIDetective-Portable-<version>.zip`. It prints the exe size and the full output path, and
exits non-zero if anything fails.

```
.\build.ps1 -Configuration Debug      # debug build
.\build.ps1 -SkipClean                # incremental, faster
.\build.ps1 -Quiet                    # errors and final paths only
```

`dist\` is the portable package: copy that folder to a USB stick and it runs from there.

## Install

No administrator rights required.

```powershell
.\Install.ps1
```

This copies the app to `%LOCALAPPDATA%\Programs\ProctorAIDetective\`, creates a Start Menu shortcut, and
registers an uninstall entry so Proctor AI Detective shows up in **Settings > Apps > Installed apps** like
any normal program.

```
.\Install.ps1 -Desktop                # also add a desktop shortcut
.\Install.ps1 -StartWithWindows       # start at sign-in (HKCU ...\CurrentVersion\Run)
.\Install.ps1 -Force                  # close a running instance instead of refusing
.\Install.ps1 -Machine                # Program Files, all users -- needs an ALREADY elevated shell
.\Install.ps1 -Source C:\some\folder  # install from an unzipped package elsewhere
```

`-Machine` falls back to a per-user install, with an explanation, if the session is not elevated.
Running `Install.ps1` again upgrades in place; it is safe to repeat.

If PowerShell refuses to run the script at all (`...cannot be loaded because running scripts is
disabled on this system`), run it as:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Install.ps1
```

## Uninstall

```powershell
& "$env:LOCALAPPDATA\Programs\ProctorAIDetective\Uninstall.ps1"
```

or use **Settings > Apps > Installed apps > Proctor AI Detective > Uninstall**.

It removes the install folder, both shortcuts, the autostart value and the uninstall registry key.
`-Quiet` suppresses output; `-Force` closes a running instance. Uninstalling something that is not
installed reports that and exits 0.

---

## Running it headless

Useful when scanning several machines, or scripting it around an assessment.

```powershell
ProctorAIDetective.exe --scan                  # JSON to stdout
ProctorAIDetective.exe --json report.json      # JSON to a file
ProctorAIDetective.exe --text report.txt       # the human-readable report
ProctorAIDetective.exe --selftest              # built-in checks, no scan
```

| Switch | Effect |
|---|---|
| `--no-browser` | Skip UI Automation tab reading. Faster, and cannot be slowed by a busy browser. |
| `--primary-only` | Report Parakeet AI only, not the wider tool class. |
| `-v`, `--verbose` | Scan progress to stderr. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clear |
| `2` | Suspicious |
| `3` | Detected (running) |
| `1` | The scan itself failed |

### Reading the exit code from PowerShell

This is a **GUI-subsystem** binary, so double-clicking it does not flash a console window. The
side effect is that **PowerShell does not wait for it**, and `$LASTEXITCODE` is left empty:

```powershell
.\ProctorAIDetective.exe --scan
$LASTEXITCODE          # '' - empty, not 0. Do not branch on this.
```

Use `Start-Process -Wait -PassThru`, which is reliable:

```powershell
$p = Start-Process .\ProctorAIDetective.exe -ArgumentList '--scan' `
                   -Wait -PassThru -NoNewWindow
switch ($p.ExitCode) {
    0 { 'clear' }
    2 { 'suspicious - look at the evidence' }
    3 { 'detected' }
    1 { 'the scan failed' }
}
```

Piping also forces PowerShell to wait, so `... --scan | Out-Null; $LASTEXITCODE` works too.
`cmd.exe` and bash wait normally, so `%ERRORLEVEL%` and `$?` are reliable there without
any of this.

This caught out the project's own CI on its first run, which is why it is documented here
rather than left to be rediscovered.

---

## SmartScreen: what you will see on first run

The executable is **not code-signed**. On a machine where it has not been seen before, Windows will
show a blue dialog:

> **Windows protected your PC**
> Microsoft Defender SmartScreen prevented an unrecognised app from starting.
> Running this app might put your PC at risk.

Click **More info**, then **Run anyway**. There is no setting that removes this warning, and no
trick in the installer that suppresses it — SmartScreen is reacting to the absence of a reputable
code-signing certificate, which is exactly what it is for.

**The only real fix is to sign the binary**, and the cheapest route is now
**Microsoft Trusted Signing** (rebranded Azure Artifact Signing): about USD 10/month, with the
key held in a cloud HSM so there is no USB token to post around. It is available to verified
US, Canadian, EU and UK organisations with a few years of verifiable operating history.

Parakeet AI itself is signed this way, which is a neat demonstration that it is within reach of
a small company: its certificate chains through `Microsoft ID Verified CS EOC CA 03` and carries
a **three-day** lifetime, which is the service's signature behaviour.

The traditional alternative is an OV or EV certificate from a commercial CA (roughly USD
200-900/year). Two things changed recently and are worth knowing before paying for EV:

* **Since June 2023**, every publicly-trusted code-signing private key must live on hardware
  certified to FIPS 140-2 Level 2 or Common Criteria EAL4+. The old "download a .pfx" workflow
  no longer exists; you get a USB token or a cloud HSM.
* **Since 2024, EV no longer buys instant SmartScreen reputation.** Reputation now accrues by
  file hash and download volume for OV and EV alike. EV is still required for kernel-mode
  driver signing, which does not apply here.

So on day one a signed build still shows a SmartScreen prompt — it just names a verified
publisher instead of "Unknown publisher", and the reputation clock starts. Because the hash
changes every release, that clock restarts each time.

Whatever you use, **always timestamp** (`/tr <url> /td SHA256`), or every signature stops
validating the moment the certificate expires.

If you are deploying this inside an organisation, signing with your own internal certificate and
pushing that certificate through policy is the normal answer, and avoids SmartScreen entirely on
managed machines.

Until then: the honest mitigation is that you can build it yourself from this source and compare
hashes, rather than trusting a binary somebody handed you.

---

## Why .NET Framework 4.8 (net48), and not .NET 8

This is the central shipping decision, and it was made on measurements, not taste.

| | net48 | net8.0-windows self-contained |
|---|---|---|
| Output size | **~1 MB** (plus a 21 KB `signatures.json`) | **68 MB** zipped, 154 MB on disk |
| Runtime to install on the target | **none** | none (bundled) — but it is the 68 MB |
| Trimmable | n/a | **no** |
| Works on a locked-down machine with no admin | **yes** | yes |

.NET Framework 4.8 is **preinstalled on every Windows 10 1903 and later, and every Windows 11**.
That is not "usually available" — it is an in-box OS component. So targeting it means the app is a
handful of small files that run anywhere, with nothing to download and nothing to install.

The .NET 8 alternative cannot be slimmed down, because the SDK refuses:

```
error NETSDK1175: Windows Forms is not supported or recommended with trimming enabled.
```

A framework-dependent .NET 8 build would be small, but then it needs the .NET 8 Desktop Runtime
installed on the target machine — which is precisely the "the application should be installable on
any Windows machine" requirement it would break.

Everything the app needs is in the framework: `System.Management` (WMI), `UIAutomationClient`
(browser tabs), `System.Net`, the registry, and P/Invoke. **No NuGet package ships in the output.**
The one `PackageReference` in the project (`Microsoft.NETFramework.ReferenceAssemblies`) is marked
`PrivateAssets="all"` and exists only so the project builds on a machine with just the SDK — no
Visual Studio, no targeting pack, and in CI.

---

## How detection actually works

Detection is five independent scanners producing **signals**. A signal is one observation, with a
confidence **tier**, two separate scores, and the **state** it speaks to.

### The two scores, and why there are two

Every signal carries both:

* **Attribution (0-100)** — "is this **Parakeet AI specifically**?"
* **Class score (0-100)** — "is this **something in the capture-evading AI-assistant class**?"

They are separate because the decisive technical observation and the identification are different
facts. Discovering that a window is excluded from screen capture proves that *something* is hiding
from capture. It does not say *what*. Password managers do it. Zoom's share toolbar does it. Netflix
does it.

**So every hidden-window and overlay signal carries `Attribution = 0` by construction.** Not as a
tuning choice — as a structural property. `C1.capture_excluded`, `C2.capture_monitor`,
`D1.clickthrough_overlay` and `D2.app_cloaked` all set attribution to literally zero in the source.
The consequence is that it is *arithmetically impossible* for this tool to accuse someone of running
Parakeet AI because 1Password hid a window. The accusation can only ever come from an identity
signal — a certificate, a version resource, a registered URL scheme — and those are checked
separately.

The class score of a hidden-window signal is promoted from 75 to 90 only when an *independent,
Strong-or-better, non-window* signal has already attributed the owning process to a vendor. A
window title is not allowed to do that promoting (see "a defect found by testing" below).

### Vendor categories, and why ChatGPT is not scored

Every vendor in `signatures.json` carries a `category`:

| Category | Meaning | How it scores |
|---|---|---|
| `interview-copilot` | A tool of the capture-evading class this app exists to find. | Normally. |
| `general-assistant` | A mainstream AI assistant: ChatGPT, Claude, Microsoft Copilot, Gemini. | **Zero on both axes, always.** |

The second row is a safety property, not a convenience. Several hundred million people run
ChatGPT and Claude for ordinary work; they do not hide from screen capture and they are not
marketed for defeating interviews. Scoring "ChatGPT is installed" as evidence of cheating would
generate false accusations at enormous scale against people doing nothing wrong.

So the rule is absolute and enforced in exactly one place — `CategoryPolicy.Apply()`, which runs
after every scanner and before the score engine, rather than being left to each scanner to
remember. A general-assistant signal is forced to `Attribution = 0`, `ClassScore = 0`, `Tier =
Weak`, and has an explanatory note appended to its detail text.

They are still **reported**, on their own line, because someone invigilating a closed-book
assessment may legitimately want to know an AI assistant is open:

```
General AI assistants seen: Claude (Anthropic) (running, and open in a browser),
ChatGPT (OpenAI) (name resolved recently, no process seen). These are ordinary
productivity tools that do not hide from screen capture, so they score nothing and
have not affected any verdict above...
```

This is not a blind spot. The window scanner's `C1.capture_excluded` signal is **vendor-blind**:
if ChatGPT — or anything else — ever hid a window from screen capture, `C1` fires on the observed
behaviour alone. Behaviour is judged on behaviour; identity never buys an exemption.

### The four tiers

| Tier | Meaning |
|---|---|
| **Definitive** | Would survive a hostile review on its own. Cryptographic or vendor-written identity. |
| **Strong** | Hard to produce by accident, easy to produce deliberately if you control the machine. |
| **Moderate** | Consistent with the conclusion; also consistent with several innocent explanations. |
| **Weak** | Corroboration only. Cannot carry a verdict, by arithmetic, not by convention. |

### The four states

| State | Question it answers |
|---|---|
| `Installed` | Is it on this machine? |
| `Running` | Is it executing right now? |
| `Evading` | Is *something* hiding itself from screen capture? |
| `None` | Historical trace only — contributes to no verdict. |

Keeping these apart is what lets the app say "installed, autostart-registered, **not running**"
without screaming DETECTED — which is exactly the state the reference machine was in.

### Signal catalogue

#### Process scanner (`process`)

Signals are grouped by *(vendor, rule, executable)* rather than per process, because every product
in this class is Electron and runs 6-10 processes off one binary. The pid list is preserved in the
detail text. First match wins per executable per vendor: `A1` beats `A2` beats `A3` beats `A4`.

| Id | Tier | Attr | Class | State | What it observes, and why that tier |
|---|---|---|---|---|---|
| `A1.signer` | Definitive | 95 (**98** if the certificate thumbprint also matches) | 90 | Running | The running executable's **Authenticode signer subject** matches the vendor. This is the strongest thing on the list: a signer subject is bound to a private key the vendor holds. Renaming the file, moving it, or editing its resources does not touch it. 98 when the exact thumbprint matches too, 95 when only the subject does — a certificate roll should not silently demote a real hit. |
| `A2.versioninfo` | Definitive | 90 | 85 | Running | `CompanyName` or `LegalCopyright` in the **version resource** matches. Written at build time by the vendor's own build. Definitive rather than Strong because a version resource is not something a different product sets by coincidence — but it *can* be edited with a resource editor, which is why it ranks below the signature. |
| `A3.path` | Strong | 70 | 65 | Running | The image is running **from the vendor's install directory**. The folder name is written by the vendor's installer. Strong and not Definitive because a user can copy any program into that folder. |
| `A3.cmdline` | Moderate | 40 | 35 | Running | A vendor path fragment appears in the **command line**, used **only when the image path could not be read at all**. Deliberately restricted: if the path resolved, matching the command line too would flag a text editor that merely *opened a file* in the Parakeet folder. A command-line mention is an argument, not an identity. |
| `A4.name` | Moderate | 45 | 40 | Running | The **process name** matches a known executable name. Moderate because a filename is the single easiest thing in this entire list to change — and the primary target has already changed its own. |
| `B1.blankname` | Strong | **10** | 45 | Running | The executable's base name consists **entirely of invisible codepoints** and renders as nothing in Task Manager. Strong: concealing your own name is not an accident. **Attribution 10, near zero on purpose**: this proves a program is hiding its identity, it does not say *which* program. Any software can be renamed this way. This is the signal that defeats the primary target's actual shipped evasion — its main executable is literally named `U+2800 BRAILLE PATTERN BLANK` + `.exe`. |
| `C1.urlscheme` | Definitive | 92 | 85 | **Installed** | A **custom URL-scheme handler** (e.g. `parakeetai://`) is registered and points at a file that exists on disk. The scheme name is chosen by the vendor and written by the vendor's installer, so it identifies the product **even when the executable has been renamed to something unreadable**. Marked `Installed` and *nothing else*, so it structurally cannot move the "running" verdict. |
| `C1.urlscheme.stale` | Moderate | 40 | 35 | Installed | Same registration, but the target **does not exist**. That is what an uninstall leaves behind. Evidence it *was* installed, not that it *is*. |
| `C2.urlscheme.running` | Definitive | 95 | 90 | Running | The executable that the registered URL scheme points at **is running now**. Identity from the installer, liveness from the process list, joined by exact path. |

#### Window scanner (`window`) — all behavioural, all `Attribution = 0` except the title

| Id | Tier | Attr | Class | State | What it observes, and why that tier |
|---|---|---|---|---|---|
| `C1.capture_excluded` | Strong | **0** | 75, or **90** when an independent Strong+ signal already attributed the process | Evading + Running | `GetWindowDisplayAffinity` returns `WDA_EXCLUDEFROMCAPTURE` (`0x11`). The window is **invisible to screen sharing and screenshots while remaining visible on the physical screen**. This is the decisive technical observation of the whole tool. Strong and not Definitive because legitimate software does it too — hence the allowlist. |
| `C2.capture_monitor` | Moderate | **0** | 45 | Evading + Running | `WDA_MONITOR` — the older, cruder "render black in captures" mode. Moderate: it is much more commonly a DRM artefact than an evasion. |
| `D1.clickthrough_overlay` | Moderate | **0** | 40 | Evading | A topmost, layered, click-through, no-activate window: the shape of an always-on-screen overlay you cannot click. Moderate because that is also the shape of a dozen legitimate HUDs. |
| `D2.app_cloaked` | Weak | **0** | 20 | Evading | DWM reports the window as `DWM_CLOAKED_APP` **without** `DWM_CLOAKED_SHELL`. Weak on purpose: `CLOAKED_SHELL` is the normal state of every suspended UWP app — 20-22 of them on an idle desktop — so including it would manufacture constant false positives. Only the app-initiated cloak is even slightly interesting. |
| `B1.window_title` | Moderate | 50 (primary vendor only) | 45 | Running | A window title contains the vendor name, matched both raw and with invisible codepoints flattened, so `Parakeet<U+2800>AI` cannot slip past `Parakeet AI`. **Never higher than Moderate**: a window title is a string any program can set to anything. |

#### Browser scanner (`browser`)

| Id | Tier | Attr | Class | State | What it observes, and why that tier |
|---|---|---|---|---|---|
| `G1.app-window` | Strong | 80 | 70 | Running | A browser process was launched with `--app=<vendor url>`. A command line is fixed at launch, so this is a window open for that exact origin right now. **Proof when present, meaningless when absent** — see limitations. |
| `G2.tab-url` | Strong | 75 | 65 | Running | The vendor's **host** is in the address bar, or a **tab in the tab strip** is named after the vendor — including a *background* tab the user is not looking at. Matching is on the host, never on a substring of the whole URL. |
| `G2.signin-handoff` | Moderate | 55 | 50 | Running | An absolute vendor URL is **embedded inside another URL** — an OAuth `redirect_uri` mid-sign-in. Real evidence, but it is a hand-off in progress, not the site being open, so it is reported one tier down. |
| `G3.window-title` | Moderate | 55 | 50 | Running | The browser's own window title names the vendor. Costs milliseconds, needs no accessibility API. Moderate because a page title is content any website can set to any string. |
| `H1.extension` | Moderate | 50 | 45 | **Installed** | A known extension id exists in a Chromium profile's `Extensions` folder. Proves installation in that profile only — Chromium keeps the folder after an extension is disabled. |

**Browser history is deliberately not read.** History answers "was this visited at some point",
which is the one thing this product must never conflate with "is it running right now". A link
clicked last Tuesday is not evidence about this interview.

#### Network scanner (`network`) — corroboration only

| Id | Tier | Attr | Class | State | What it observes, and why that tier |
|---|---|---|---|---|---|
| `E1.net.endpoint.N` | Weak | **0** | 15 | Running | A live TCP connection to an address a vendor hostname resolves to *right now*. Weak and attribution 0 because `*.parakeet-ai.com` lives on **shared anycast infrastructure** — during testing, Chrome held a connection to the same address while Parakeet was installed but not running. |
| `E2.net.process.N` | Strong | 70 | 65 | Running | The same connection, **plus** the owning process independently matches the vendor by thumbprint / signer / version resource / path. Evidence is ranked inside the signal and a path-only match is labelled as weaker than the tier suggests. |
| `F1.dns.cache.N` | Weak | **0** | 12 | `None` | A vendor hostname is in the DNS resolver cache. `State = None`, so it contributes to **no verdict at all** — it is context for a human reader, nothing more. |

---

## The scoring arithmetic

Four questions are scored independently, from the same pile of signals:

| Axis | Signals used | Score used |
|---|---|---|
| **Running — attribution** | `State` includes `Running` | Attribution |
| **Running — class** | `State` includes `Running` | Class |
| **Installed — attribution** | `State` includes `Installed` | Attribution |
| **Evading — class** | `State` includes `Evading` | Class |

The arithmetic is deliberately boring, because this tool makes claims about people.

1. **Select** the signals whose `StateAxis` matches the question being asked. A signal with the
   wrong state is not down-weighted — it is not in the sum at all.
2. **Apply the allowlist multiplier** to each signal's score (next section). A suppressed signal
   contributes 0 but stays visible in the exported evidence, so the suppression is auditable.
3. **Noisy-OR within each tier:**

   ```
   subtotal = 100 * (1 - PRODUCT(1 - s_i / 100))
   ```

   Independent hints accumulate, nothing is double-counted, and the result approaches but never
   reaches 100. Two 50s make 75, not 100.
4. **Cap each tier.** Weak is capped at **30** absolutely. A **lone** Moderate — exactly one
   Moderate signal contributing — is capped at **25**. Only *contributing* signals count as group
   members, so a suppressed signal cannot silently turn a lone Moderate into a pair and lift its cap.
5. **Noisy-OR the four tier subtotals together** the same way, and round.
6. **Definitive floor.** Any unsuppressed Definitive signal that *actually scores on this axis*
   raises the total to at least **70**.
7. **Verdict:** `>= 70` **Detected**, `>= 25` **Suspicious**, below that **Clear**.

### The four invariants

These are structural properties of the arithmetic above, not advisory guidelines:

1. **Any number of Weak signals, alone, tops out at 30.** Weak evidence can never produce a
   detection, however much of it there is.
2. **A lone Moderate signal lands on exactly 25** — the Suspicious boundary, never more. One
   ambiguous observation is never allowed to read as a detection.
3. **A single unsuppressed Definitive signal always reaches at least 70.** Real proof is never
   diluted away by the absence of corroboration.
4. **Behavioural signals carry `Attribution = 0`, so they can never move an attribution axis.**
   The tool cannot accuse a named product on the basis of a hidden window. This is the invariant
   that keeps the other three from being dangerous.

If scoring an axis throws for any reason, that axis is reported as **unanswered** with a note in
Limitations — never as a clean result.

---

## The allowlist, and why a listed name can make things *worse*

Plenty of entirely legitimate software hides windows from screen capture: the Zoom share toolbar,
password managers, DRM video playback, OBS's own preview, the UAC secure desktop. Without an
allowlist this tool would accuse everybody of everything.

But an allowlist keyed on a process **name** is a trivial bypass: rename your binary
`nvcontainer.exe` and you are invisible. So the allowlist is keyed on the **triple
(name, signer, path)** and behaves as a **tripwire**, not a bypass:

| What matched | Outcome | Multiplier |
|---|---|---|
| Name matches nothing | `NotListed` | **x1.00** |
| Name + signer + path match, entry marked `verified` | `Suppressed` | **x0.00** |
| Name + signer + path match, entry **not** `verified` | `DownRanked` | **x0.35** |
| Name matches but the signer or path **contradicts** the entry | **`Masquerade`** | **x1.75** |

**The escalation is the whole point.** An allowlisted name wearing the wrong certificate is *more*
suspicious than a process nobody has ever heard of. Something calling itself `Zoom.exe` that is not
signed by Zoom is a finding, not an exemption.

Two deliberate refinements:

* **A masquerade raises the class score only, never attribution.** A thing pretending to be NVIDIA
  is not evidence of Parakeet AI specifically.
* **"Unreadable" is not "wrong."** `X509Certificate.CreateFromSignedFile` *throws* on
  catalog-signed files, which is how most in-box Windows binaries are signed —
  `explorer.exe`, `ctfmon.exe` and `TextInputHost.exe` are all on the allowlist and all
  catalog-signed. An unreadable signature is therefore treated as `DownRanked` (x0.35), not
  `Masquerade` (x1.75). Escalating it would escalate half of Windows on every scan. Down-ranking
  still refuses to hard-suppress, so a signature-stripped impostor wearing an allowlisted name keeps
  35% of its score rather than walking off with a free pass.

---

## Editing `signatures.json`

`signatures.json` sits **next to the exe** and is read at startup. Edit it and re-run — **no
rebuild**. That is the point: a new product appears, or a vendor rolls a certificate, and the fix
is a text edit on the machine that needs it.

```jsonc
{
  "version": "2026.10.07.1",     // bump this; it is stamped into every report
  "updated": "2026-10-07",

  "invisibleCodepoints": [ 10240, 8203, 65279, 160, ... ],

  "vendors": [
    {
      "key": "parakeet",             // stable id, used internally; do not reuse one
      "name": "Parakeet AI",         // what a human sees in the report
      "primaryTarget": true,         // see below -- at most one should be true
      "confidence": "verified",      // "verified" or "heuristic" -- see below
      "source": "Observed first-hand 2026-10-07 on ParakeetAI 3.9.106 ...",

      "signerContains":   ["PARAKEETAI d.o.o."],          // A1  Authenticode subject substring
      "certThumbprints":  ["59C214EE8843...04892F12"],    // A1+ exact SHA-1 thumbprint
      "companyNames":     ["ParakeetAI"],                 // A2  version resource CompanyName (exact)
      "copyrightContains":["ParakeetAI"],                 // A2  LegalCopyright substring
      "urlSchemes":       ["parakeetai"],                 // C1/C2 registered protocol handler
      "processNames":     ["<U+2800>.exe"],               // A4  executable file name
      "pathFragments":    ["\\Programs\\parakeetai-desktop\\"],  // A3 install path substring
      "windowTitleContains": ["ParakeetAI", "Parakeet AI"],      // B1 window title substring
      "hostnames":        ["parakeet-ai.com"],            // E1/E2/F1 network + DNS
      "webFragments":     ["parakeet-ai.com"],            // G2/G3 browser URL host + tab title
      "extensionIds":     ["dknakjaafflhhloliodcoiafncnejdaa"]   // H1 Chromium extension id
    }
  ],

  "allowlist": [
    { "processName": "Zoom.exe", "expectedSigner": "Zoom",
      "expectedPathFragment": "", "verified": true,
      "note": "Meeting controls / screen-share toolbar." }
  ]
}
```

### Rules worth knowing before you edit

* **Empty arrays match nothing.** A signature with no populated fields fires zero signals — it does
  not match everything. (Verified: a deliberately empty "poison" vendor matched 0 of 436 processes.)
* **Empty *strings* inside an array are ignored**, for the same reason. `"pathFragments": [""]` is
  not a wildcard.
* **`primaryTarget: true` is what unlocks attribution scoring.** Every signal for a non-primary
  vendor carries `Attribution = 0` and shows up only on the class axes. Set exactly one vendor
  primary; that is the product the report is *about*.
* **`confidence` is a statement to the reader, not an input to the maths.**
  * `"verified"` — observed first-hand on a real install. The `source` field must say when, where
    and how.
  * `"heuristic"` — inferred from an installer, a release page, a config file, or the
    electron-builder default layout, and **never observed running**. A heuristic entry **must not
    be treated as proof** by anyone reading a report. Most non-primary vendors in the shipped file
    are heuristic and say so.
* **`signerContains` is the field worth getting right.** It is the only one that survives renaming
  the executable, moving the install directory and editing the version resource.
* **Allowlist entries: leaving both `expectedSigner` and `expectedPathFragment` empty while setting
  `verified: true` creates a name-only hard suppression** — which is exactly the bypass the triple
  was designed to prevent. See the known defects below.

---

## Known limitations, and how to evade this tool

Written plainly, because a reviewer needs this more than they need the feature list.

### Evasions that defeat it completely

* **Use a second device.** A phone, a tablet, a second laptop. Nothing in this tool can see it.
  This is both the easiest evasion and by far the most common real-world usage pattern.
* **Do not run it during the scan.** The scan is a point in time. Start the assistant afterwards.
* **Run it in another session, VM, or as another user.** Out of scope by construction.

### Evasions that defeat specific signals

* **Rename the executable and move it** out of the vendor's install directory. Defeats `A3.path`
  and `A4.name`. Does **not** defeat `A1.signer` — the certificate travels with the file.
* **Strip the Authenticode signature** (or re-sign with your own certificate). Defeats `A1` and
  degrades `A2`. The cost is that the binary is now unsigned, which is itself conspicuous — but this
  tool does not currently treat "no signature at all" as a signal in its own right, because
  `CreateFromSignedFile` throws identically on *catalog-signed* system binaries, and reporting
  "unsigned" from a throw would be a false claim about half of Windows.
* **Give the file an ordinary name.** Defeats `B1.blankname`. Note this is a *de*-escalation the
  primary target chose not to make — it ships the blank name deliberately.
* **Turn off `setContentProtection`.** Defeats `C1.capture_excluded` entirely. The window then shows
  up in a screen share, which is the thing the user was trying to avoid, so this is a real
  trade-off rather than a free bypass.
* **Delete the URL-scheme registration** from `HKCU\Software\Classes`. Defeats `C1`/`C2`.
* **Use the web version in a normal browser tab** and never install anything. Then the only signals
  available are the browser ones, which depend on UI Automation and are the least reliable part of
  the tool (below).

### Defects in the shipped data that a reviewer should know about

These are **data problems in `signatures.json`**, fixable by editing the file, and they were found
by testing rather than by reading:

* **`obs64.exe` is allowlisted with an empty signer, an empty path fragment, and
  `verified: true`.** That is a name-only hard suppression (x0.00). Renaming a capture-evading
  binary to `obs64.exe` would zero *every* signal attached to it — including `A1.signer`, which is
  otherwise rename-proof. Several other entries have the same empty-empty-but-`verified` shape.
  **Fix:** give these entries a real `expectedSigner` or `expectedPathFragment`, or set
  `verified: false` so they down-rank (x0.35) instead of suppressing.
* **`chrome.exe` and `msedge.exe` are allowlisted `verified: true` with signer-only keys.** This is
  correct for DRM playback — a genuinely Google-signed Chrome that sets capture protection is
  Netflix, not an interview cheat. But it means that if the *web* build of a capture-evading
  assistant ever applies capture protection through a browser window, `C1.capture_excluded` is
  silently deleted for that window. **Fix:** path-pin those two entries, or rely on the browser
  scanner for that case.
* **`rt.speechmatics.com` does not resolve.** The real endpoints are `*.rt.speechmatics.com`
  (e.g. `eu2.rt.speechmatics.com`), so the bare parent name is NXDOMAIN and can **never** produce a
  TCP match for `E1`/`E2`. It still works for `F1`, which matches subdomains. Separately: Speechmatics
  is a general-purpose commercial speech-to-text vendor with many customers, so its presence names a
  *capability*, not a product — which is why the tier does not move on it.

### Defects in the logic a reviewer should know about

* **`E2.net.process` is scored at Attribution 70, which *is* the Detected threshold.** The design
  intent was that network signals alone can never produce a Detected verdict; the specified score of
  70 contradicts that by exactly one point. It is implemented as specified rather than silently
  shaved to 69, because a tool whose value is auditability should not disagree with its own
  specification in an unexplained magic number. In practice a signer or thumbprint match means the
  process scanner reports it independently anyway; the case that actually bites is a **path-only**
  match reaching Detected off "a binary in a folder named `\Programs\parakeetai-desktop\` has a
  socket open". **Fix:** one character in the score, or drop path-only matches to Moderate.
* **The network scanner contaminates its own evidence.** Resolving the vendor hostnames seeds the
  DNS cache with them — including ones that fail, which Windows negative-caches identically. The
  cache is read *before* any lookup, repeat scans within a session discount hostnames this process
  resolved, and every scan that resolves emits a limitation saying so. **The residual hole is
  cross-launch:** a fresh launch within the TTL can see the previous launch's footprints as `F1`
  signals. This was observed directly, including a deliberately bogus subdomain reappearing as `F1`
  on a later scan. `F1` carries `State = None` precisely because of this.
* **`D1.clickthrough_overlay` fires on 1x1 windows.** The rule is "non-zero size", implemented
  literally rather than with an invented area threshold. On the reference machine the only 1x1 hit
  was `explorer.exe`'s `ThumbnailDeviceHelperWnd` and the allowlist caught it — but a
  non-allowlisted app with a 1x1 topmost layered no-activate helper would fire unsuppressed.
* **`G1.app-window` is proof-when-present only.** When Chrome is already running,
  `chrome --app=<url>` is relayed over IPC to the existing process and the launcher exits, so no
  surviving process carries the switch. **The absence of `G1` means nothing at all.**

### Blind spots the tool reports about itself

The app does not hide these; it writes them into the report's Limitations list:

* **Browser tab enumeration is unreliable in both directions.** On the reference machine Edge
  exposed all 16 tabs on one probe and zero minutes later on the same window; Chrome does the same.
  A UI Automation dump of a Chrome window returning zero tabs showed the tab strip **genuinely
  absent** from the tree, correlating with a busy renderer rather than with the window being
  minimised or occluded. When the tab strip cannot be read, the address bar and window title carry
  the signal, and the gap is **stated** rather than hidden. "0 tabs" is never silently treated as
  "no match" — a tabbed window always has at least one tab.
* **Window display-affinity queries can fail.** On failure the Win32 out parameter is *undefined*,
  so the window is forced to `WDA_NONE` and recorded as **UNKNOWN — a stated blind spot — never as
  "not hidden."** `ERROR_INVALID_WINDOW_HANDLE` (1400) is routine: a window closed between
  enumeration and the query. The count appears in the report.
* **`WDA_EXCLUDEFROMCAPTURE` requires Windows 10 2004 (build 19041) or newer.** On older builds the
  decisive signal is unavailable and the report says so.
* **Without elevation, roughly a third of process image paths cannot be read.** Measured on the
  reference machine: 165 of 444 unresolved at medium integrity, versus 5 of 436 elevated. The
  elevation limitation fires with those real numbers attached. Elevation was *not* needed to catch
  the primary target, which runs as the same user.
* **WMI command lines are a bonus, never a requirement.** Non-elevated, Windows populates
  `CommandLine` for only about 167 of 430 processes.
* **Firefox, Brave, Opera and Vivaldi are ported but untested** — not installed on the machine the
  tool was developed and verified against.

---

## Responsible use

This tool produces a report that can be used to accuse someone of cheating. Treat it accordingly.

* **Get consent before you scan.** Tell the person what will run on their machine and what it looks
  at, before it runs. "Consent" obtained after the fact is not consent.
* **Show the scanned person the same report you see.** Not a verdict — the full evidence list, with
  the tiers, the scores and the limitations. If the evidence will not survive being shown to the
  person it is about, it should not be used against them.
* **Never auto-act on a verdict.** No automatic fail, no automatic flag, no automatic email. The
  output is an input to a human judgement, and a human has to be accountable for that judgement.
* **"Clear" is not a clearance and "Detected" is not a conviction.** Clear means this machine, this
  session, this instant, showed nothing — with a phone sitting just out of frame as the obvious
  uncovered case. Detected means a named program with a matching certificate was found running;
  the person may still have an explanation you have not thought of. Ask.
* **Do not retain the report longer than the decision needs it.** It contains a full process and
  window inventory of someone's personal machine, including software that has nothing to do with
  you.
* **It reads; it does not write.** The app does not kill processes, modify the registry outside its
  own installer, phone home, or upload anything. The DNS resolver cache is read non-destructively.

---

## Project layout

```
proctor-AI-detective\
  build.ps1              build, stage dist\, produce the portable zip
  Install.ps1            per-user installer (no admin), -Machine for all users
  Uninstall.ps1          removes everything Install.ps1 created
  signatures.json        the signature database -- edit without rebuilding
  README.md              this file
  src\ProctorAIDetective\
    ProctorAIDetective.csproj     net48, AnyCPU, WinForms, Nullable enable
    app.manifest         asInvoker, PerMonitorV2, longPathAware, UTF-8
    Core\                Evidence, Signatures, SignatureLoader, Allowlist,
                         ScoreEngine, MiniJson
    Native\              NativeMethods, Win32Constants, ProcessInfo
    Scanners\            Process, Window, Browser, Network, InstallResolver
    Ui\                  the WinForms shell and evidence grid
  ref\                   standalone prototypes, kept for reading only (gitignored)
  dist\                  build output (gitignored)
```

`System.Text.Json` is not used anywhere: it does not exist on net48. JSON is handled by `MiniJson`
in `Core\`, with `System.Web.Extensions`' `JavaScriptSerializer` as a fallback.
