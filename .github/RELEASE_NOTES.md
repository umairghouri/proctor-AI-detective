### Install

Download the zip below, **unblock it** (right-click → Properties → Unblock), extract, then
either run `ProctorAIDetective.exe` directly or run `Install.ps1` for a Start Menu entry and a
proper uninstaller.

No .NET runtime to install, no administrator rights, no service, no driver.

> **Windows will show a SmartScreen warning on first run**, because the executable is not
> code-signed. Choose **More info → Run anyway**.

### What it does

Reports whether **Parakeet AI** — or another screen-capture-evading AI assistant — is running
on this machine, by enumerating windows that ask Windows to exclude them from screen capture
(`WDA_EXCLUDEFROMCAPTURE`). That catches the whole product class generically, including tools
it has no signature for.

It reports **three separate verdicts** — running now, installed, and hiding from screen
capture — because "installed but not running" is a real and common state that a single score
cannot express without implying guilt.

### Read this before acting on a result

A clear result is **not** proof that no assistance was used. The tool sees one Windows user
session, on one device, at one moment. It cannot see a second laptop, a phone, a tablet, a
virtual machine, another user account, or a person off camera.

A detection is evidence that **specific software is present or running** — not a finding of
misconduct. The README documents how the tool can be evaded, deliberately and in detail.

Mainstream assistants (ChatGPT, Claude, Copilot, Gemini) are reported as a plain observation
and score **zero** towards every verdict. They are ordinary productivity software.

### Provenance

Built by CI from the tagged source on a clean `windows-latest` runner, including a
clean-machine scan that must come back clear before the release is published.
