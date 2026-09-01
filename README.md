<p align="center">
  <img src="https://raw.githubusercontent.com/alrigroup/.github/main/alrigroup.svg" width="120" />
</p>

<h1 align="center">ARAPIAUTH</h1>
<p align="center"><strong>OAuth2 / OIDC Authentication Gateway</strong></p>
<p align="center">
  <a href="https://github.com/alrigroup/alrios"><img alt="ALRIOS" src="https://img.shields.io/badge/Powered%20by-ALRIOS-blue?style=flat-square" /></a>
  <img alt="Language" src="https://img.shields.io/badge/language-C-00599C?style=flat-square" />
  <img alt="License" src="https://img.shields.io/badge/license-Proprietary-red?style=flat-square" />
</p>

---

## Overview

**ARAPIAUTH** is a lightweight OAuth2/OIDC authentication gateway built in C for the [ALRIOS](https://github.com/alrigroup/alrios) platform. It acts as the public-facing authentication API, handling token exchange and SSO flows while delegating secure credential storage to the internal ARAUTH vault.

### Features

- 🔑 **OAuth2 Flows** — Authorization Code, Client Credentials, and Token Exchange
- 🌐 **SSO Gateway** — Single Sign-On across all ALRIOS-powered applications
- 🔗 **ARAUTH Integration** — Delegates secure operations to the internal ARAUTH vault
- ⚡ **Native Performance** — Written in C with minimal overhead
- 🛡️ **Token Validation** — JWT verification and session management

## Building

```bash
armake build arapiauth
```

## Part of ALRIOS

ARAPIAUTH is a core component of the [ALRIOS Operating System](https://github.com/alrigroup/alrios).

---

<p align="center">© 2025 ALRI Group — All rights reserved.</p>
