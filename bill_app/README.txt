Dependency	What it does	Internet needed?
Google Fonts (DM Sans, DM Mono, Noto Sans Tamil)	App typography	First load only
All app logic, GST engine, data storage	Everything else	Never

Once fonts are cached by the browser, the app works fully offline. But if you open it on a brand new browser that never loaded it before, fonts will fall back to system fonts — the app still works, just looks slightly different.

Let me make it 100% truly standalone — embed the fonts as base64 directly into the HTML so it needs zero internet, ever.
Ran 5 commands

Zero external URLs. 108 KB, fully self-contained.
Ran a command, read a file

Yes — now 100% standalone. Zero internet required, ever.

Here's the full picture:

What was removed:

    Google Fonts CDN link (the only external dependency)

What replaced it — system fonts already on your computer:
OS	Sans-serif font used	Monospace	Tamil
Windows 10/11	Segoe UI	Consolas	Nirmala UI
Windows 7/8	Segoe UI	Consolas	Latha
macOS	SF Pro (system)	SF Mono	Tamil MN
Linux (Ubuntu)	Ubuntu	Ubuntu Mono	TSCu_Paranar

These fonts are built into the OS — no download, no CDN, no network call at all.

Complete offline setup — nothing to install:

    Save the billing-app.html file to your Desktop or any folder
    Double-click to open in Chrome or Edge
    Fill setup form → Save & Start
    Done — works fully offline forever

For safety, do these two things after setup:

    Weekly backup: Settings → Export All Data (JSON) → save to USB or external drive
    Don't clear browser data (History/Cookies/Cache) without exporting first — that would erase your billing data

To move to another computer: Copy the HTML file + your JSON backup to the new machine, open the HTML, go to Settings → Import Data, select your JSON file — all invoices, products and customers restored instantly.