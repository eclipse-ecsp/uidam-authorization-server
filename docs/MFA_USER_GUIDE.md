# Multi-Factor Authentication (MFA) — User Guide

> **Product:** UIDAM Authorization Server  
> **Applies to:** All tenants with MFA policy enabled  
> **Last updated:** June 2026

---

## Table of Contents

1. [Overview](#1-overview)
2. [Supported Authenticator Apps](#2-supported-authenticator-apps)
3. [MFA Enrollment — Step-by-Step](#3-mfa-enrollment--step-by-step)
   - [Step 1 — Log in with your username and password](#step-1--log-in-with-your-username-and-password)
   - [Step 2 — Set up your authenticator app](#step-2--set-up-your-authenticator-app)
   - [Step 3 — Scan the QR code (or enter the key manually)](#step-3--scan-the-qr-code-or-enter-the-key-manually)
   - [Step 4 — Verify your first code](#step-4--verify-your-first-code)
   - [Step 5 — Save your backup codes](#step-5--save-your-backup-codes)
4. [Logging In with MFA (Daily Use)](#4-logging-in-with-mfa-daily-use)
5. [Backup Codes — What They Are and How to Use Them](#5-backup-codes--what-they-are-and-how-to-use-them)
6. [Recovery Options — When You Cannot Access Your Authenticator](#6-recovery-options--when-you-cannot-access-your-authenticator)
   - [Option A — Email Security Code Recovery](#option-a--email-security-code-recovery)
   - [Option B — Backup Code Recovery](#option-b--backup-code-recovery)
   - [Option C — Contact Your Administrator](#option-c--contact-your-administrator)
7. [Re-Enrollment After Recovery](#7-re-enrollment-after-recovery)
8. [App-Specific Setup Instructions](#8-app-specific-setup-instructions)
   - [Google Authenticator](#google-authenticator)
   - [Microsoft Authenticator](#microsoft-authenticator)
   - [Authy](#authy)
   - [Duo Mobile](#duo-mobile)
9. [Frequently Asked Questions](#9-frequently-asked-questions)
10. [Security Best Practices](#10-security-best-practices)

---

## 1. Overview

Multi-Factor Authentication (MFA) adds a second layer of security to your account. After entering your username and password, you are prompted for a **time-based, one-time passcode (TOTP)** — a 6-digit code that refreshes every 30 seconds inside an authenticator app on your phone.

Even if someone steals or guesses your password, they cannot log in without also having physical access to your enrolled device.

```
┌─────────────────────────────────────────────────────────────────┐
│               MFA Authentication Flow                           │
│                                                                 │
│  [Username + Password]  →  ✅ Correct?                          │
│                                  │                             │
│                                  ▼                             │
│                       [Enter 6-digit TOTP code]                │
│                                  │                             │
│                          ✅ Code valid?                         │
│                                  │                             │
│                                  ▼                             │
│                         [Access Granted]                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Supported Authenticator Apps

UIDAM MFA is compatible with any **RFC 6238 TOTP** authenticator app. The following are tested and recommended:

| App                       | Platform            | Notes                                              |
|---------------------------|---------------------|----------------------------------------------------|
| **Google Authenticator**  | iOS / Android       | Simple, offline, no cloud backup (free)            |
| **Microsoft Authenticator** | iOS / Android / Windows Phone | Cloud backup, push notifications (free) |
| **Authy**                 | iOS / Android / Desktop / Chrome | Multi-device sync, encrypted cloud backup (free) |
| **Duo Mobile**            | iOS / Android       | Enterprise-grade, integrates with Duo Security     |

> **Any other TOTP app** (e.g., 1Password, Bitwarden, LastPass Authenticator, FreeOTP) will also work as long as it supports TOTP (RFC 6238).

---

## 3. MFA Enrollment — Step-by-Step

Enrollment happens automatically the **first time you log in** when your tenant has MFA enabled. You will be guided through a setup wizard.

---

### Step 1 — Log in with your username and password

1. Navigate to the application login page.
2. Enter your **username** and **password** as usual.
3. Click **Sign In**.

If MFA is required for your account, you will be redirected to the **MFA setup wizard** instead of directly to the application.

---

### Step 2 — Set up your authenticator app

Before you can scan the QR code, make sure you have an authenticator app installed on your phone or device. If you have not installed one yet, see [Section 8 — App-Specific Setup Instructions](#8-app-specific-setup-instructions) for download links and per-app guidance.

---

### Step 3 — Scan the QR code (or enter the key manually)

You will see the **"Set Up Multi-Factor Authentication"** page:

```
┌──────────────────────────────────────────────────┐
│  🔐 Set Up Multi-Factor Authentication            │
│                                                  │
│  Step 1: Install an authenticator app             │
│  Step 2: Scan the QR code below                  │
│                                                  │
│           ┌─────────────┐                        │
│           │  [QR CODE]  │                        │
│           └─────────────┘                        │
│                                                  │
│  Can't scan? Enter this key manually:            │
│  ABCD EFGH IJKL MNOP QRST                        │
│                                                  │
│  Step 3: Enter the 6-digit code your app shows   │
│  [ _ _ _ _ _ _ ]                                │
│                                                  │
│           [ Verify & Activate ]                  │
└──────────────────────────────────────────────────┘
```

**Option A — Scan the QR code (recommended)**

1. Open your authenticator app.
2. Tap **"+"** or **"Add account"** (see [Section 8](#8-app-specific-setup-instructions) for exact steps per app).
3. Choose **"Scan QR code"**.
4. Point your phone's camera at the QR code on the screen.
5. The app creates an entry labelled with your application name (e.g., `UIDAM - <TenantName>`).

**Option B — Enter the key manually**

If you cannot scan the QR code (e.g., you are setting up a desktop authenticator):

1. In your authenticator app, choose **"Enter key manually"** or **"Enter setup key"**.
2. Enter your **Account name** (your username or email).
3. Copy the **Manual Key** displayed on the setup page (the space-separated string under the QR code).
4. Ensure the type is set to **Time-based (TOTP)**.
5. Tap **Add**.

> **Important:** The setup key is a one-time secret. Do not share it with anyone. If you suspect it was exposed, contact your administrator to revoke and re-issue it.

---

### Step 4 — Verify your first code

1. Your authenticator app now shows a **6-digit code** that rotates every 30 seconds.
2. Type the current code into the **"Enter 6-digit code"** field on the setup page.
3. Click **Verify & Activate**.
4. If the code is correct, enrollment is confirmed and you move to the backup codes screen.

> **Tip:** Act quickly — codes expire every 30 seconds. If you see the timer about to expire, wait for the next code before submitting.

If you enter an incorrect code, you will see:
> _"Invalid code. Please check your authenticator app and try again."_

Simply check the current code shown in your app and re-enter it.

---

### Step 5 — Save your backup codes

After a successful verification, you will be shown your **one-time backup codes** (if enabled for your tenant):

```
┌──────────────────────────────────────────────────────┐
│  ✅ MFA Enrollment Complete                           │
│                                                      │
│  ⚠️ Save these backup codes now. Each code can        │
│  be used once. They will NOT be shown again.         │
│                                                      │
│   ABC12-DEF34    GHI56-JKL78                         │
│   MNO90-PQR12    STU34-VWX56                         │
│   YZA78-BCD90    EFG12-HIJ34                         │
│   KLM56-NOP78    QRS90-TUV12                         │
│                                                      │
│  ☐ I have saved my backup codes in a safe place      │
│                                                      │
│           [ Continue to Application ]                │
└──────────────────────────────────────────────────────┘
```

**You must save these codes before clicking "Continue."** Recommended storage options:

- ✅ Printed on paper and locked in a safe
- ✅ Saved in a password manager (e.g., 1Password, Bitwarden, KeePass)
- ✅ Stored in a secure note on a different device
- ❌ Do **not** save them in the same app or device as your authenticator

Check the confirmation box **"I have saved my backup codes in a safe place"** to enable the Continue button.

---

## 4. Logging In with MFA (Daily Use)

Once enrolled, every login follows this sequence:

### Step 1 — Enter credentials
1. Go to the application login page.
2. Enter your **username** and **password**.
3. Click **Sign In**.

### Step 2 — Enter your TOTP code

You will be redirected to the **Two-Factor Authentication** challenge page:

```
┌─────────────────────────────────────────┐
│  🔐 Two-Factor Authentication            │
│                                         │
│        👤 your.username                 │
│                                         │
│  Open your authenticator app and enter  │
│  the 6-digit code shown for UIDAM        │
│                                         │
│         ⏱ [30-second timer ring]        │
│                                         │
│  [ _ _ _ _ _ _ ]                       │
│                                         │
│         [ Verify Code ]                 │
│                                         │
│  ─────────────────────────────────────  │
│  Lost access to your authenticator?     │
│  [ Account Recovery ]                   │
└─────────────────────────────────────────┘
```

1. Open your authenticator app on your phone.
2. Find the entry named **UIDAM** (or your tenant's application name).
3. Type the **6 digits** shown into the code field.
4. Click **Verify Code** before the 30-second timer expires.
5. You are logged in.

### Entering the code — tips

| Situation | What to do |
|-----------|-----------|
| Code just expired (timer near 0) | Wait for the next code — it refreshes automatically |
| Code rejected even though it looks correct | Check that your phone's clock is set to **automatic / network time** |
| Typing is slow | Use copy-paste — the field accepts pasted digits |
| You see `Invalid code. Please try again.` | Re-open your app, get a fresh code, and re-submit immediately |

---

## 5. Backup Codes — What They Are and How to Use Them

### What are backup codes?

Backup codes are **pre-generated, single-use identity-verification tokens** generated automatically at enrollment and shown **only once**. They have one specific purpose in UIDAM:

> **Backup codes are not a way to skip MFA or log in without a code. They are an identity proof used during the account recovery flow to authorise re-enrollment on a replacement device.**

When you verify a backup code during recovery, UIDAM:
1. Confirms the code is valid and marks it as consumed (single-use).
2. **Revokes your current MFA enrollment.**
3. **Redirects you immediately to the enrollment setup page** so you can link a new device.

You still need to complete a fresh enrollment scan with your authenticator app on the new device before you can log in.

### When backup codes are needed

| Situation | What happened | Backup code lets you… |
|-----------|--------------|----------------------|
| **Uninstalled the authenticator app** | Your TOTP codes are gone | Re-enroll on the same or a different app |
| **Got a new phone** | Old app no longer available | Re-enroll on the new device's app |
| **Lost or stolen phone** | Cannot generate codes | Re-enroll on a replacement device |
| **Authenticator app data was wiped** | App reset / factory reset | Re-enroll after reinstalling the app |

### What backup codes do NOT do

- ❌ They do **not** let you log in directly, bypassing the authenticator.
- ❌ They do **not** generate TOTP codes.
- ❌ They do **not** restore your old authenticator setup — after using one, you **always** re-enroll from scratch.

### Properties of backup codes

- Each code can be used **exactly once** — it is invalidated immediately after use.
- A standard set contains **8–10 codes**.
- They are stored securely (hashed) in the user management service — the plain-text codes are shown only at enrollment.
- Using one code does not consume the others; remaining codes stay valid until used or re-enrollment generates a fresh set.

### How backup codes fit into the recovery flow

Backup codes are **step 2 of the recovery sequence** (when enabled for your tenant). You cannot use a backup code until after you have first verified your identity via an email security code:

```
[Account Recovery] → [Email Code ✅] → [Backup Code ✅] → [Re-Enrollment Setup]
```

See [Option B — Backup Code Recovery](#option-b--backup-code-recovery) in Section 6 for the full step-by-step.

> **⚠️ Each backup code is single-use.** Cross off or delete the code you used from your saved list. Once all codes are consumed, only email recovery or an administrator reset can restore access.

---

## 6. Recovery Options — When You Cannot Access Your Authenticator

If you cannot produce a valid TOTP code, click **"Account Recovery"** on the challenge page. You will be taken to the recovery options screen:

```
┌──────────────────────────────────────────────────────────┐
│  🆘 Account Recovery                                      │
│                                                          │
│  Can't access your authenticator app?                    │
│  Choose a recovery option below.                         │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ 📧 Email me a security code                        │  │
│  │ We'll send a one-time 6-character code to your     │  │
│  │ registered email address.                          │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ 👤 Contact your administrator                      │  │
│  │ Ask your IT helpdesk or tenant admin to reset       │  │
│  │ your MFA enrollment.                               │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│              ← Back to authenticator code entry          │
└──────────────────────────────────────────────────────────┘
```

---

### Option A — Email Security Code Recovery

This is the **primary self-service recovery** option.

1. On the recovery page, click **"📧 Email me a security code"**.
2. A **6-character one-time security code** is sent to your registered email address within seconds.
3. You are taken to the **"Enter Security Code"** page:

```
┌──────────────────────────────────────────────────────┐
│  📧 MFA Recovery — Check Your Email                  │
│                                                      │
│  ✅ A security code has been sent to your            │
│     registered email address.                        │
│                                                      │
│  Security Code:                                      │
│  [  _  _  _  _  _  _  ]                             │
│                                                      │
│          [ Verify Code ]                             │
│                                                      │
│  Didn't receive a code?                              │
│  [ Resend ] (available after 60-second cooldown)     │
└──────────────────────────────────────────────────────┘
```

4. Check your inbox for an email from the system (check Spam/Junk if needed).
5. Enter the **6-character code** — it is case-insensitive (type it in uppercase or lowercase).
6. Click **Verify Code**.
7. On success:
   - If backup codes are enabled for your tenant → you are prompted to enter a backup code as a second verification step.
   - If backup codes are disabled → your enrollment is revoked and you are taken directly to the **re-enrollment setup** page.

**Cooldown:** You can only request a new code once every **60 seconds** (configurable per tenant). If you click "Resend" too quickly, a countdown timer shows how many seconds remain.

---

### Option B — Backup Code Recovery

This path is available **only after** completing email verification (Option A) when your tenant has backup codes enabled. It is the **second step** of the two-step recovery sequence — not a standalone bypass.

**Recovery sequence:**
```
[Account Recovery page]
        │
        ▼
[Email security code sent] → [Enter email code ✅]
        │
        ▼
[Enter backup code ✅]
        │
        ▼
[Enrollment REVOKED → Re-enrollment setup page]
```

**Steps:**

1. Complete [Option A](#option-a--email-security-code-recovery) first — your email security code **must** be verified successfully before the backup-code page appears.
2. After the email code is accepted, you are automatically forwarded to the **Backup Code** entry page:

```
┌──────────────────────────────────────────────────────┐
│  🔑 Enter Backup Code                                │
│                                                      │
│  Enter one of the backup codes you saved             │
│  when you first set up MFA.                          │
│                                                      │
│  Backup Code:                                        │
│  [ _________________________ ]                       │
│                                                      │
│         [ Verify Backup Code ]                       │
└──────────────────────────────────────────────────────┘
```

3. Enter one of your saved single-use backup codes exactly as written.
4. Click **Verify Backup Code**.
5. On success:
   - The backup code is **consumed** (cannot be reused).
   - Your existing MFA enrollment is **revoked**.
   - You are redirected to the **MFA Enrollment Setup** page to register a new authenticator app on your replacement device.
   - A fresh set of backup codes is generated during this re-enrollment.

> **Important:** A valid backup code does **not** grant access to the application. It only proves your identity so that UIDAM can safely revoke the old enrollment and allow you to re-enroll on a new device.

If the backup code is incorrect, you will see:
> _"Invalid backup code. Please check the code you saved at enrollment and try again."_

---

### Option C — Contact Your Administrator

If you no longer have access to your registered email or backup codes:

1. Contact your **IT helpdesk** or **tenant administrator**.
2. Provide your **username** and explain that you have lost access to your authenticator app.
3. The administrator can reset your MFA enrollment from the user management portal.
4. Once reset, your next login will trigger the enrollment wizard again.

---

## 7. Re-Enrollment After Recovery

After any successful recovery flow (email + backup code, or admin reset), your MFA enrollment is **revoked**. You will be redirected automatically to the enrollment setup page to register a new device.

Follow the same steps as [Section 3](#3-mfa-enrollment--step-by-step):

1. Scan the new QR code with your authenticator app (or a replacement app on a new device).
2. Enter the first TOTP code to verify.
3. **Save your new backup codes** — the previous set is no longer valid.

---

## 8. App-Specific Setup Instructions

### Google Authenticator

**Download:**
- iOS: [App Store](https://apps.apple.com/app/google-authenticator/id388497605)
- Android: [Google Play](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2)

**Setup Steps:**

1. Open Google Authenticator.
2. Tap the **"+"** (plus) button in the bottom-right corner.
3. Choose **"Scan a QR code"**.
4. Point your camera at the QR code on the UIDAM enrollment page.
5. The account appears as **"UIDAM - \<TenantName\>: \<your-username\>"**.
6. A 6-digit code is now displayed. Enter it on the UIDAM verification page.

**Entering the key manually:**

1. Tap **"+"** → **"Enter a setup key"**.
2. **Account name:** Enter your username (e.g., `john.doe@company.com`).
3. **Your key:** Paste the Manual Key from the UIDAM enrollment page (remove spaces if prompted).
4. **Type of key:** Select **Time based**.
5. Tap **Add**.

**Notes:**
- Google Authenticator does **not** sync codes to the cloud by default. If you lose your phone, you lose access to codes (use backup codes for recovery).
- As of recent versions, you can optionally back up to your Google Account — enable this in Settings.

---

### Microsoft Authenticator

**Download:**
- iOS: [App Store](https://apps.apple.com/app/microsoft-authenticator/id983156458)
- Android: [Google Play](https://play.google.com/store/apps/details?id=com.azure.authenticator)

**Setup Steps:**

1. Open Microsoft Authenticator.
2. Tap **"+"** (top-right) → select **"Other account (Google, Facebook, etc.)"**.
3. Choose **"Scan QR code"**.
4. Point your camera at the QR code on the UIDAM enrollment page.
5. The account appears in the app. Tap it to reveal the current 6-digit code.
6. Enter the code on the UIDAM verification page.

**Entering the key manually:**

1. Tap **"+"** → **"Other account"** → **"OR ENTER CODE MANUALLY"**.
2. **Account name:** Enter your username.
3. **Secret key:** Paste the Manual Key from the UIDAM page.
4. Tap **Finish**.

**Notes:**
- Microsoft Authenticator supports **encrypted cloud backup** to Microsoft account — highly recommended to enable so you can restore accounts on a new phone.
- Navigate to **Settings → Cloud Backup** (iOS: iCloud Backup; Android: Cloud Backup) to enable.

---

### Authy

**Download:**
- iOS: [App Store](https://apps.apple.com/app/twilio-authy/id494168017)
- Android: [Google Play](https://play.google.com/store/apps/details?id=com.authy.authy)
- Desktop: [authy.com/download](https://authy.com/download/) (Windows / macOS / Linux)
- Chrome extension: Available from Chrome Web Store

**Setup Steps:**

1. Open Authy and sign in with your phone number (required for multi-device sync).
2. Tap **"+"** (Add Account) or the **menu icon** → **"Add Account"**.
3. Tap **"Scan QR Code"**.
4. Scan the QR code from the UIDAM enrollment page.
5. Give the account a name (e.g., **UIDAM**) and choose a logo colour.
6. Tap **Save**.
7. Enter the 6-digit code shown in Authy on the UIDAM verification page.

**Entering the key manually:**

1. Tap **"Add Account"** → **"Enter key manually"**.
2. Paste the Manual Key from the UIDAM page.
3. Tap **Add Account**, then set a name and save.

**Notes:**
- Authy supports **multi-device sync** — install on your phone and desktop and codes are available everywhere.
- You can also register a **backup phone number** so you can recover access to Authy if you lose your primary device.
- Enable **"Allow Multi-device"** in Authy's Settings → Devices if you want sync across devices.

---

### Duo Mobile

**Download:**
- iOS: [App Store](https://apps.apple.com/app/duo-mobile/id422663827)
- Android: [Google Play](https://play.google.com/store/apps/details?id=com.duosecurity.duomobile)

**Setup Steps:**

1. Open Duo Mobile.
2. Tap the **"+"** icon (top-right corner).
3. When asked what you are adding, tap **"Use QR code"**.
4. Scan the QR code from the UIDAM enrollment page.
5. The account is added as a **TOTP account** (labelled as a third-party account).
6. Tap the account to reveal the 6-digit code, then enter it on the UIDAM verification page.

**Entering the key manually:**

1. Tap **"+"** → **"Manually add account"**.
2. Enter your **Username** (account name).
3. Enter the **Secret Key** from the UIDAM manual key field.
4. Tap **Save**.

**Notes:**
- Duo Mobile is primarily designed for use with the **Duo Security platform** (push notifications, etc.), but UIDAM uses it as a standard TOTP generator.
- On newer versions, look for **"Add account"** → **"Third-party account"** to add non-Duo TOTP tokens.
- Duo supports **account restore** from an encrypted backup if you have Duo's account recovery enabled.

---

## 9. Frequently Asked Questions

**Q: My code says "Invalid code" even though I entered it correctly. What should I do?**

The most common cause is a clock drift between your phone and the server. TOTP codes are time-sensitive.

- iOS: Settings → General → Date & Time → enable **Set Automatically**.
- Android: Settings → General Management → Date and Time → enable **Automatic date and time**.

Wait for the next code (up to 30 seconds) and try again.

---

**Q: I got a new phone. What happens to my MFA?**

Your old enrollment is tied to the authenticator app on your old phone. Options:

1. **If you still have your old phone:** Open your old authenticator app, find the UIDAM entry, and write down the manual key (if the app allows export). Re-add it to the app on your new phone using "Enter key manually".
2. **If you have Authy or Microsoft Authenticator with cloud backup enabled:** Log in to the same account on your new phone — accounts restore automatically without any re-enrollment.
3. **If you no longer have your old phone (lost/stolen/reset):** Use the email security code + backup code recovery flow (see [Section 6](#6-recovery-options--when-you-cannot-access-your-authenticator)). A valid backup code revokes your old enrollment and sends you to the re-enrollment setup page to link your new device.

---

**Q: What exactly do backup codes do in UIDAM?**

Backup codes are **re-enrollment authorisation tokens**, not login bypass codes. They are used exclusively inside the recovery flow:

- You prove your identity with an email security code **first**.
- Then you enter a backup code as a **second proof** that you are the legitimate account owner.
- On success, your old enrollment is **revoked** and you are taken to the enrollment setup page to link a new authenticator on your replacement device.

Backup codes do not grant access to the application — you must complete re-enrollment and then log in normally.

---

**Q: How long is a TOTP code valid?**

Each code is valid for **30 seconds**. The countdown ring on the challenge page shows the remaining time. The server allows a small tolerance window (±1 code period) to account for slight clock differences.

---

**Q: Can I use the same authenticator app for multiple UIDAM tenants?**

Yes. Each tenant creates a separate TOTP entry in your authenticator app. You will see multiple entries named `UIDAM - <TenantName>`. Use the entry that matches the tenant you are logging into.

---

**Q: What happens if I use all my backup codes?**

Once all backup codes are consumed, you must contact your administrator to reset your MFA enrollment, or use email recovery (if your registered email is still accessible). After reset, new backup codes are generated at re-enrollment.

---

**Q: Can I skip MFA enrollment?**

This depends on your tenant's MFA policy:
- **Enforced (MANDATORY):** MFA enrollment is required. You cannot log in without completing it.
- **Conditional:** MFA may be required only for certain roles or under specific conditions.

Contact your administrator if you believe MFA is incorrectly applied to your account.

---

**Q: I lost my backup codes. Can I generate new ones?**

Backup codes can only be regenerated after completing the full re-enrollment flow or at the administrator's discretion. Contact your IT helpdesk if you have exhausted your codes.

---

**Q: The email security code is not arriving. What should I do?**

1. Check your **Spam / Junk** folder.
2. Make sure the correct email address is registered to your account.
3. Wait 60 seconds (the resend cooldown) and click **Resend**.
4. If the issue persists, contact your administrator to verify your registered email address.

---

## 10. Security Best Practices

| Practice | Why it matters |
|----------|---------------|
| **Save backup codes offline** | If your phone is lost, backup codes are what let you re-enroll on a replacement device without an admin |
| **Use a password manager for backup codes** | Prevents loss while keeping them secure and accessible |
| **Enable cloud backup in your authenticator app** | Protects against losing TOTP accounts when you change phones |
| **Never share your TOTP codes** | Codes are time-bound and single-use, but sharing them in real-time still enables attacks |
| **Never share the manual key (secret)** | Unlike codes, the secret is permanent and allows anyone to generate codes for your account |
| **Keep your phone's clock on automatic time** | TOTP relies on time synchronisation; manual time settings cause code failures |
| **Do not screenshot QR codes** | Screenshots can be accessed by other apps; scan directly and discard |
| **Lock your authenticator app** | Most apps support PIN/biometric lock — enable it |
| **Report lost devices immediately** | Tell your administrator so they can revoke and reset your MFA enrollment |

---

*For technical issues, contact your system administrator or refer to the [UIDAM Authorization Server documentation](../README.md).*
