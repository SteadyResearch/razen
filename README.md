# Razen desktop UI

Investigation launch screen built with React, TypeScript, and Vite for a future Tauri desktop host.

```sh
npm install
npm run dev
```

`npm run build` checks TypeScript and produces static assets in `dist/`.

Includes agent/copilot briefs, target origin validation, request/time limits, templates, local draft history, and search (Ctrl/Cmd+K). Creating an investigation opens a draft plan; it does not execute an agent or send requests. The starting plan is placeholder UI content.

Drafts use browser local storage. Do not enter secrets. Replace the draft adapter with project-scoped Tauri commands when integrating the engine. The Rust engine must validate permissions and scope independently.

For Tauri integration, use `http://127.0.0.1:5173` as the development URL and `dist/` as frontend assets. The packaged frontend needs no Node server. Native IPC, traffic capture, secrets, policy, and AI execution are not implemented yet.
