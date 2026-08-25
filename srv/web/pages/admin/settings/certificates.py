import os

from srv.web.app import *
from srv.web.app import _spawn_background_command
from werkzeug.exceptions import HTTPException
from srv.certbot_manager import (
    cancel_certbot_job,
    certbot_account_status,
    delete_certbot_certificate,
    get_certbot_account_job,
    get_certbot_job,
    certbot_runtime_hint,
    set_certbot_job_certificate_id,
    start_certbot_account_job,
    start_certbot_job,
)
from srv.web.pages.admin.settings.common import settings_page

MAX_CERTIFICATE_UPLOAD_BYTES = 2 * 1024 * 1024

MATERIAL_ICON_PATHS = {
    "add": "M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z",
    "copy": "M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z",
    "delete": "M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM8 9h8v10H8V9zm7.5-5-1-1h-5l-1 1H5v2h14V4z",
    "restart": "M12 5V1L7 6l5 5V7c3.31 0 6 2.69 6 6s-2.69 6-6 6-6-2.69-6-6H4c0 4.42 3.58 8 8 8s8-3.58 8-8-3.58-8-8-8z",
}


def material_icon(name):
    return (
        '<svg class="md-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">'
        f'<path d="{MATERIAL_ICON_PATHS[name]}"></path></svg>'
    )


def absolute_server_path(value):
    text = str(value or "").strip()
    return bool(text and (text.startswith("/") or Path(text).is_absolute()))


def remove_managed_files(record):
    if not record or not int(record.get("managed_upload") or 0):
        return
    try:
        managed_root = CERTIFICATE_DIR.resolve()
    except OSError:
        return
    for key in ("certificate_path", "private_key_path"):
        path = Path(str(record.get(key) or ""))
        try:
            resolved = path.resolve()
            if resolved.parent == managed_root and resolved.is_file():
                resolved.unlink()
        except OSError:
            pass


def save_uploaded_pair(certificate_file, private_key_file):
    if not certificate_file or not str(certificate_file.filename or "").strip():
        raise ValueError("Choose a certificate file to upload.")
    if not private_key_file or not str(private_key_file.filename or "").strip():
        raise ValueError("Choose a private key file to upload.")
    CERTIFICATE_DIR.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid4().hex
    certificate_tmp = CERTIFICATE_DIR / f".{token}.certificate.tmp"
    private_key_tmp = CERTIFICATE_DIR / f".{token}.private-key.tmp"
    certificate_path = CERTIFICATE_DIR / f"{token}.crt"
    private_key_path = CERTIFICATE_DIR / f"{token}.key"

    def save_limited(item, destination):
        total = 0
        with destination.open("wb") as output:
            while True:
                chunk = item.stream.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_CERTIFICATE_UPLOAD_BYTES:
                    raise ValueError("Certificate files may not exceed 2 MB each.")
                output.write(chunk)

    try:
        save_limited(certificate_file, certificate_tmp)
        save_limited(private_key_file, private_key_tmp)
        validate_tls_certificate(certificate_tmp, private_key_tmp)
        os.chmod(certificate_tmp, 0o644)
        os.chmod(private_key_tmp, 0o600)
        os.replace(certificate_tmp, certificate_path)
        os.replace(private_key_tmp, private_key_path)
        return str(certificate_path), str(private_key_path)
    except Exception:
        for path in (certificate_tmp, private_key_tmp, certificate_path, private_key_path):
            try:
                if path.is_file():
                    path.unlink()
            except OSError:
                pass
        raise


def save_certificate_record(action, record):
    name = str(request.form.get("name") or "").strip()
    if not name:
        raise ValueError("Certificate name is required.")
    if len(name) > 255:
        raise ValueError("Certificate name must be 255 characters or fewer.")
    duplicate = query_one(
        "SELECT id FROM certificates WHERE name=%s AND id<>%s LIMIT 1",
        (name, int(record["id"]) if record else 0),
    )
    if duplicate:
        raise ValueError("A certificate with that name already exists.")

    managed_upload = 0
    new_paths = None
    if action == "upload":
        new_paths = save_uploaded_pair(
            request.files.get("certificate_file"),
            request.files.get("private_key_file"),
        )
        certificate_path, private_key_path = new_paths
        managed_upload = 1
    else:
        certificate_path = str(request.form.get("certificate_path") or "").strip()
        private_key_path = str(request.form.get("private_key_path") or "").strip()
        if not absolute_server_path(certificate_path) or not absolute_server_path(private_key_path):
            raise ValueError("Certificate and private key paths must be absolute server paths.")
        validate_tls_certificate(certificate_path, private_key_path)

    try:
        if record:
            execute(
                """
                UPDATE certificates
                SET name=%s, certificate_path=%s, private_key_path=%s, managed_upload=%s,
                    certbot_name=NULL, certbot_domains=NULL
                WHERE id=%s
                """,
                (name, certificate_path, private_key_path, managed_upload, record["id"]),
            )
            refresh_certificate_assignments(record["id"])
            if (
                int(record.get("managed_upload") or 0)
                and (record.get("certificate_path") != certificate_path or record.get("private_key_path") != private_key_path)
            ):
                remove_managed_files(record)
            return "Certificate updated."
        certificate_id = execute(
            """
            INSERT INTO certificates (name, certificate_path, private_key_path, managed_upload)
            VALUES (%s,%s,%s,%s)
            """,
            (name, certificate_path, private_key_path, managed_upload),
        )
        return f"Certificate added with ID {certificate_id}."
    except Exception:
        if new_paths:
            remove_managed_files(
                {
                    "managed_upload": 1,
                    "certificate_path": new_paths[0],
                    "private_key_path": new_paths[1],
                }
            )
        raise


def unique_certificate_name(base_name):
    base = str(base_name or "Certificate").strip()[:240] or "Certificate"
    candidate = base
    suffix = 2
    while query_one("SELECT id FROM certificates WHERE name=%s LIMIT 1", (candidate,)):
        ending = f" ({suffix})"
        candidate = base[:255 - len(ending)] + ending
        suffix += 1
    return candidate


def register_certbot_job(job):
    if not job or job.get("status") != "success":
        return job
    validate_tls_certificate(job["certificate_path"], job["private_key_path"])
    hostnames = list(job.get("hostnames") or [])
    existing = query_one("SELECT * FROM certificates WHERE certbot_name=%s LIMIT 1", (job.get("certbot_name"),))
    if existing:
        execute(
            """
            UPDATE certificates
            SET certificate_path=%s, private_key_path=%s, certbot_domains=%s
            WHERE id=%s
            """,
            (
                job["certificate_path"],
                job["private_key_path"],
                json.dumps(hostnames),
                existing["id"],
            ),
        )
        refresh_certificate_assignments(existing["id"])
        set_certbot_job_certificate_id(job["id"], existing["id"])
        job["certificate_id"] = int(existing["id"])
        return job
    display_name = unique_certificate_name("Let's Encrypt - " + (hostnames[0] if hostnames else job.get("certbot_name", "Certificate")))
    certificate_id = execute(
        """
        INSERT INTO certificates (
            name, certificate_path, private_key_path, managed_upload, certbot_name, certbot_domains
        ) VALUES (%s,%s,%s,0,%s,%s)
        """,
        (
            display_name,
            job["certificate_path"],
            job["private_key_path"],
            job["certbot_name"],
            json.dumps(hostnames),
        ),
    )
    set_certbot_job_certificate_id(job["id"], certificate_id)
    job["certificate_id"] = int(certificate_id)
    return job


def can_restart_openpagingserver():
    return (
        os.name != "nt"
        and hasattr(os, "geteuid")
        and os.geteuid() == 0
        and Path("/run/systemd/system").exists()
        and systemd_unit_exists(OPS_SYSTEMD_UNIT)
    )


def schedule_openpagingserver_restart():
    if not can_restart_openpagingserver():
        raise RuntimeError("OpenPagingServer cannot be restarted automatically on this server.")

    def restart_service():
        _spawn_background_command(["systemctl", "restart", OPS_SYSTEMD_UNIT])

    timer = threading.Timer(1.0, restart_service)
    timer.daemon = False
    timer.start()


def finish_certbot_job(job, data):
    certificate_id = str(job.get("certificate_id") or "")
    if not certificate_id:
        raise ValueError("The deployed certificate is not registered yet.")
    enable_web = bool(request.form.get("enable_web_https"))
    enable_api = bool(request.form.get("enable_api_https")) and data.get("api_http_enable", "0") == "1"
    enable_sip = bool(request.form.get("enable_sip_tls")) and data.get("enable_insecure_sip", "0") == "1"
    selected = enable_web or enable_api or enable_sip
    renewed_in_use = bool(job.get("renew_certificate_id") and certificate_usage(certificate_id))
    restart_needed = selected or renewed_in_use
    if restart_needed and not can_restart_openpagingserver():
        raise RuntimeError("The certificate was deployed, but OpenPagingServer cannot be restarted automatically on this server.")
    if enable_web:
        set_certificate_for_service("web", certificate_id)
        save_setting("webserver_https_enable", "1", "HTTPs Enable (0/1)")
        save_setting("webserver_http_to_https", "1", "Automatically redirect HTTP requests to HTTPS (0/1)")
    if enable_api:
        set_certificate_for_service("api", certificate_id)
        save_setting("api_https_enable", "1", "Enable REST API over HTTPS (0/1)")
        save_setting("api_http_to_https", "1", "Automatically redirect API HTTP requests to HTTPS (0/1)")
    if enable_sip:
        set_certificate_for_service("sip", certificate_id)
        save_setting("enable_secure_sip", "1", "Enable SIP over TLS (0/1)")
    if restart_needed:
        schedule_openpagingserver_restart()
    return restart_needed


def expiration_label(record):
    if record.get("error"):
        return record["error"], "certificate-invalid"
    expires_at = record.get("expires_at")
    if expires_at is None:
        return "Expiration unavailable", "certificate-invalid"
    prefix = "Expired" if record.get("expired") else "Expires"
    return f'{prefix} <span class="certificate-countdown" data-expires="{int(expires_at)}"></span>', "certificate-expired" if record.get("expired") else ""


def renewal_label(record):
    renewal_at = record.get("renewal_at")
    if not record.get("certbot_name") or renewal_at is None:
        return ""
    renewal_date = datetime.utcfromtimestamp(int(renewal_at)).strftime("%Y-%m-%d %H:%M UTC")
    return f'<div class="certificate-renewal">Renewal date: {h(renewal_date)}</div>'


def render_page(user, message="", error=""):
    records = certificate_records()
    current_settings = settings()
    certbot_runtime = certbot_runtime_hint()
    certbot_is_available = bool(certbot_runtime.get("available"))
    certbot_account = certbot_account_status() if certbot_is_available else {"ready": False}
    rows = []
    for record in records:
        usage = certificate_usage(record["id"])
        usage_labels = {"web": "Web", "api": "API", "sip": "SIP"}
        usage_html = ", ".join(usage_labels.get(service, service) for service in usage)
        expiry_html, expiry_class = expiration_label(record)
        source = "Certbot" if record.get("certbot_name") else "Uploaded" if int(record.get("managed_upload") or 0) else "Server paths"
        if record.get("certbot_name"):
            expiry_html = renewal_label(record) or '<span class="certificate-unused">Renewal date unavailable</span>'
            try:
                certbot_domains = json.loads(record.get("certbot_domains") or "[]")
            except (TypeError, ValueError, json.JSONDecodeError):
                certbot_domains = []
            if certbot_is_available:
                update_button = (
                    f'<button type="button" class="md-icon-button certificate-certbot-renew" title="Renew certificate" aria-label="Renew certificate" '
                    f'data-id="{int(record["id"])}" data-domains="{h(json.dumps(certbot_domains))}">{material_icon("restart")}</button>'
                )
            else:
                update_button = f'<button type="button" class="md-icon-button" disabled title="Install Certbot to renew this certificate" aria-label="Renew certificate">{material_icon("restart")}</button>'
        else:
            update_button = (
                f'<button type="button" class="md-icon-button certificate-update" title="Update certificate" aria-label="Update certificate" data-id="{int(record["id"])}" '
                f'data-name="{h(record.get("name"))}" data-certificate-path="{h(record.get("certificate_path"))}" '
                f'data-private-key-path="{h(record.get("private_key_path"))}">{material_icon("restart")}</button>'
            )
        rows.append(
            f"""
            <tr class="{h(expiry_class)}">
                <td><strong>{h(record.get("name"))}</strong><div class="certificate-subject">{h(record.get("subject") or "")}</div></td>
                <td>{source}</td>
                <td>{expiry_html}</td>
                <td>{usage_html or '<span class="certificate-unused">Not in use</span>'}</td>
                <td class="certificate-actions">
                    {update_button}
                    <form method="post" onsubmit="return confirm('Delete this certificate?');">
                        <input type="hidden" name="action" value="delete">
                        <input type="hidden" name="certificate_id" value="{int(record['id'])}">
                        <button type="submit" class="md-icon-button certificate-delete" title="Delete certificate" aria-label="Delete certificate"{' disabled' if usage else ''}>{material_icon("delete")}</button>
                    </form>
                </td>
            </tr>
            """
        )
    table_body = "".join(rows) or '<tr><td colspan="5" class="certificate-empty">No certificates are available.</td></tr>'
    notice = f'<div class="certificate-notice success">{h(message)}</div>' if message else ""
    if error:
        notice = f'<div class="certificate-notice error">{h(error)}</div>'
    elif not message and certbot_runtime.get("installed") and not certbot_is_available:
        notice = f'<div class="certificate-notice warning">{h(certbot_runtime.get("error"))}</div>'
    certbot_choice = (
        '<button type="button" class="md-choice-button" id="chooseCertbotCertificate" '
        f'data-available="{1 if certbot_is_available else 0}" data-account-ready="{1 if certbot_account.get("ready") else 0}">'
        'Generate new using Certbot</button>'
    )
    web_finish_checked = "" if current_settings.get("webserver_https_enable", "0") == "1" else " checked"
    api_finish_checked = "" if current_settings.get("api_https_enable", "0") == "1" else " checked"
    sip_finish_checked = "" if str(current_settings.get("enable_secure_sip", "0") or "0") not in {"", "0"} else " checked"
    api_finish_option = """
                    <label class="md-checkbox-container"><input type="checkbox" id="certbotEnableApi"{api_checked}><span class="md-checkmark"></span><span class="md-checkbox-text">Enable HTTPS for API</span></label>
    """.format(api_checked=api_finish_checked) if current_settings.get("api_http_enable", "0") == "1" else ""
    sip_finish_option = """
                    <label class="md-checkbox-container"><input type="checkbox" id="certbotEnableSip"{sip_checked}><span class="md-checkmark"></span><span class="md-checkbox-text">Enable TLS for SIP</span></label>
    """.format(sip_checked=sip_finish_checked) if current_settings.get("enable_insecure_sip", "0") == "1" else ""
    material_spinner = """
        <svg class="md-circular-progress" viewBox="0 0 48 48" aria-hidden="true" focusable="false">
            <circle cx="24" cy="24" r="19"></circle>
        </svg>
    """
    body = f"""
    <style>
    .certificate-toolbar {{ display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom:16px; }}
    .certificate-table-wrap {{ overflow-x:auto; }}
    .certificate-table {{ width:100%; border-collapse:collapse; min-width:760px; }}
    .certificate-table th,.certificate-table td {{ padding:12px 10px; border-bottom:1px solid #EEE; text-align:left; vertical-align:middle; }}
    .certificate-table th {{ color:#555; font-weight:500; }}
    .certificate-table tr.certificate-expired {{ background:rgba(244,67,54,0.09); }}
    .certificate-table tr.certificate-invalid {{ background:rgba(255,152,0,0.09); }}
    .certificate-subject,.certificate-unused {{ color:#777; font-size:.85em; margin-top:4px; }}
    .certificate-renewal {{ color:#777; font-size:.9em; }}
    .certificate-actions {{ display:flex; gap:8px; align-items:center; }}
    .certificate-actions form {{ margin:0; }}
    .md-icon {{ width:22px; height:22px; display:block; fill:currentColor; }}
    .login-settings button.md-icon-button {{ width:40px; height:40px; min-width:40px; padding:8px; border-radius:50%; display:inline-flex; align-items:center; justify-content:center; background:transparent; color:var(--ops-accent); box-shadow:none; }}
    .login-settings button.md-icon-button:hover {{ background:rgba(25,118,210,.12); }}
    .login-settings button.md-icon-button.certificate-delete {{ background:transparent; color:#D32F2F; }}
    .login-settings button.md-icon-button.certificate-delete:hover {{ background:rgba(211,47,47,.12); }}
    .login-settings button:disabled {{ opacity:.45; cursor:not-allowed; }}
    .certificate-notice {{ padding:12px; border-radius:6px; margin-bottom:14px; }}
    .certificate-notice.success {{ background:rgba(76,175,80,.15); color:#2E7D32; }}
    .certificate-notice.error {{ background:rgba(244,67,54,.13); color:#C62828; }}
    .certificate-notice.warning {{ background:rgba(255,152,0,.16); color:#E65100; }}
    .certificate-modal-backdrop {{ display:none; position:fixed; inset:0; z-index:1700; background:rgba(0,0,0,.5); align-items:center; justify-content:center; padding:18px; box-sizing:border-box; }}
    .certificate-modal-backdrop.active {{ display:flex; }}
    .certificate-modal {{ width:min(92vw,540px); max-height:90vh; overflow:auto; background:#FFF; color:#202124; border-radius:20px; padding:24px; box-sizing:border-box; box-shadow:0 12px 36px rgba(0,0,0,.28); }}
    .certificate-modal h2 {{ margin-top:0; }}
    .certificate-modal a,.certificate-modal a:visited {{ color:var(--ops-accent); text-decoration:underline; }}
    .certificate-modal-actions {{ display:flex; gap:10px; justify-content:flex-end; margin-top:18px; flex-wrap:wrap; }}
    .certificate-modal button {{ min-height:40px; border-radius:20px; padding:0 20px; font-weight:500; letter-spacing:.01em; box-shadow:none; }}
    .certificate-modal-actions button {{ background:transparent; color:var(--ops-accent); }}
    .certificate-modal-actions button:hover {{ background:rgba(25,118,210,.1); }}
    .certificate-modal-actions button.certificate-delete {{ color:#D32F2F; }}
    .certificate-modal-actions button.certificate-delete:hover {{ background:rgba(211,47,47,.1); }}
    .certificate-modal-actions button[type="submit"],.certificate-modal-actions button#certbotFinishButton,.certificate-modal-actions button#certbotRetryButton {{ background:var(--ops-accent); color:#FFF; }}
    .certificate-choice {{ display:flex; flex-direction:column; gap:10px; margin-top:16px; }}
    .certificate-choice button.md-choice-button {{ width:100%; min-height:52px; text-align:left; border:1px solid rgba(25,118,210,.35); border-radius:12px; background:rgba(25,118,210,.08); color:var(--ops-accent); }}
    .certificate-choice button.md-choice-button:hover {{ background:rgba(25,118,210,.15); }}
    .certbot-install-command {{ display:block; padding:14px; border-radius:10px; background:rgba(0,0,0,.06); user-select:all; overflow-wrap:anywhere; }}
    .certbot-hostname-row {{ display:flex; align-items:center; gap:8px; margin-bottom:10px; }}
    .certbot-hostname-row input {{ flex:1; }}
    .login-settings button.certbot-remove-hostname {{ color:#D32F2F; }}
    .certbot-challenge {{ padding:14px; border-radius:12px; background:rgba(0,0,0,.045); margin:12px 0; }}
    .certbot-challenge-row {{ display:grid; grid-template-columns:64px minmax(0,1fr) 40px; align-items:center; gap:12px; min-height:40px; }}
    .certbot-challenge-row + .certbot-challenge-row {{ margin-top:6px; }}
    .certbot-challenge-row strong {{ line-height:40px; }}
    .certbot-challenge code {{ display:block; overflow-wrap:anywhere; user-select:all; line-height:1.4; }}
    .certbot-wait-body {{ display:flex; align-items:flex-start; gap:18px; margin-top:16px; }}
    .md-circular-progress {{ width:42px; height:42px; flex:0 0 42px; animation:certbot-spin 1.4s linear infinite; }}
    .md-circular-progress circle {{ fill:none; stroke:var(--ops-accent); stroke-width:4; stroke-linecap:round; stroke-dasharray:80 120; animation:certbot-dash 1.4s ease-in-out infinite; }}
    @keyframes certbot-spin {{ to {{ transform:rotate(360deg); }} }}
    @keyframes certbot-dash {{ 0% {{ stroke-dasharray:1 120; stroke-dashoffset:0; }} 50% {{ stroke-dasharray:80 120; stroke-dashoffset:-35; }} 100% {{ stroke-dasharray:80 120; stroke-dashoffset:-124; }} }}
    .certbot-progress-note {{ line-height:1.5; margin:0; }}
    .certbot-error {{ color:#C62828; white-space:pre-wrap; max-height:180px; overflow:auto; }}
    .certbot-success-icon {{ width:64px; height:64px; display:block; fill:#2E7D32; margin:0 auto 14px; }}
    .certbot-finish-options {{ display:flex; flex-direction:column; gap:14px; margin:18px 0; }}
    @media(max-width:600px) {{ .certbot-challenge-row {{ grid-template-columns:56px minmax(0,1fr) 40px; gap:8px; }} }}
    @media(prefers-color-scheme:dark) {{
        .certificate-table th {{ color:#BBB; }}
        .certificate-table th,.certificate-table td {{ border-bottom-color:#333; }}
        .certificate-subject,.certificate-unused,.certificate-renewal {{ color:#999; }}
        .certificate-modal {{ background:#1E1E1E; color:#E0E0E0; }}
        .certificate-modal a,.certificate-modal a:visited {{ color:#8AB4F8; }}
        .certbot-install-command {{ background:rgba(255,255,255,.07); }}
        .certbot-challenge {{ background:rgba(255,255,255,.05); }}
        .certificate-choice button.md-choice-button {{ border-color:rgba(138,180,248,.42); background:rgba(138,180,248,.1); color:#8AB4F8; }}
        .certificate-modal-actions button {{ color:#8AB4F8; }}
        .certificate-notice.success {{ color:#81C784; }}
        .certificate-notice.error {{ color:#EF9A9A; }}
        .certificate-notice.warning {{ color:#FFB74D; }}
    }}
    </style>
    <div id="certificates" class="tab-content active">
        <div class="info-card login-settings">
            <div class="certificate-toolbar">
                <div><h4>Installed certificates</h4></div>
                <button type="button" class="md-icon-button" id="newCertificateButton" title="Add certificate" aria-label="Add certificate">{material_icon("add")}</button>
            </div>
            {notice}
            <div class="certificate-table-wrap">
                <table class="certificate-table">
                    <thead><tr><th>Name</th><th>Source</th><th>Expiration / Renewal</th><th>Used by</th><th>Actions</th></tr></thead>
                    <tbody>{table_body}</tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="certificate-modal-backdrop" id="certificateChoiceModal" aria-hidden="true">
        <div class="certificate-modal login-settings">
            <h2 id="certificateChoiceTitle">Add certificate</h2>
            <div class="certificate-choice">
                {certbot_choice}
                <button type="button" class="md-choice-button" id="chooseUploadCertificate">Upload new certificate</button>
                <button type="button" class="md-choice-button" id="chooseExistingCertificate">Use existing on server</button>
            </div>
            <div class="certificate-modal-actions"><button type="button" data-close-certificate-modal>Cancel</button></div>
        </div>
    </div>

    <div class="certificate-modal-backdrop" id="certbotInstallModal" aria-hidden="true">
        <div class="certificate-modal login-settings">
            <h2>Certbot not installed</h2>
            <p>Please install Certbot using the following command as root or with sudo:</p>
            <code class="certbot-install-command">apt install certbot</code>
            <div class="certificate-modal-actions"><button type="button" data-close-certificate-modal>Cancel</button></div>
        </div>
    </div>

    <div class="certificate-modal-backdrop" id="certbotAccountModal" aria-hidden="true">
        <div class="certificate-modal login-settings">
            <h2>Set up Let's Encrypt</h2>
            <p>This information is required to register with Let's Encrypt to generate certificates. Data collection is governed by the <a href="https://letsencrypt.org/privacy/" target="_blank" rel="noopener noreferrer">Let's Encrypt Privacy Policy</a>. The Open Paging Server Project does not receive this information and is not responsible for handling SSL requests or for how this information is collected, stored, used, or handled by third parties.</p>
            <form id="certbotAccountForm">
                <div class="info-row" style="display:block"><label class="info-label" for="certbotAccountEmail">Email address</label><input type="email" id="certbotAccountEmail" autocomplete="email" maxlength="254" required></div>
                <label class="md-checkbox-container" style="margin-top:16px"><input type="checkbox" id="certbotAgreeTerms" required><span class="md-checkmark"></span><span class="md-checkbox-text">I agree to the <a href="https://letsencrypt.org/repository/" target="_blank" rel="noopener noreferrer">Let's Encrypt Subscriber Agreement</a>.</span></label>
                <label class="md-checkbox-container" style="margin-top:16px"><input type="checkbox" id="certbotEffEmail"><span class="md-checkmark"></span><span class="md-checkbox-text">Share my email with the Electronic Frontier Foundation (EFF) to receive EFF news, campaigns, and ways to support digital freedom.</span></label>
                <div id="certbotAccountError" class="certbot-error" style="margin-top:12px"></div>
                <div class="certificate-modal-actions"><button type="button" data-close-certificate-modal>Cancel</button><button type="submit" id="certbotAccountContinue">Continue</button></div>
            </form>
        </div>
    </div>

    <div class="certificate-modal-backdrop" id="certificateUploadModal" aria-hidden="true">
        <div class="certificate-modal login-settings">
            <h2>Upload new certificate</h2>
            <form method="post" enctype="multipart/form-data">
                <input type="hidden" name="action" value="upload">
                <input type="hidden" name="certificate_id" class="certificate-edit-id">
                <div class="info-row" style="display:block"><label class="info-label">Name</label><input type="text" name="name" class="certificate-edit-name" maxlength="255" required></div>
                <div class="info-row" style="display:block"><label class="info-label">Certificate</label><input type="file" name="certificate_file" accept=".crt,.cer,.pem" required></div>
                <div class="info-row" style="display:block"><label class="info-label">Private Key</label><input type="file" name="private_key_file" accept=".key,.pem" required></div>
                <div class="certificate-modal-actions"><button type="button" data-close-certificate-modal>Cancel</button><button type="submit">Upload</button></div>
            </form>
        </div>
    </div>

    <div class="certificate-modal-backdrop" id="certificateServerModal" aria-hidden="true">
        <div class="certificate-modal login-settings">
            <h2>Use existing certificate on server</h2>
            <form method="post">
                <input type="hidden" name="action" value="server">
                <input type="hidden" name="certificate_id" class="certificate-edit-id">
                <div class="info-row" style="display:block"><label class="info-label">Name</label><input type="text" name="name" class="certificate-edit-name" maxlength="255" required></div>
                <div class="info-row" style="display:block"><label class="info-label">Certificate path</label><input type="text" name="certificate_path" id="certificateServerPath" required></div>
                <div class="info-row" style="display:block"><label class="info-label">Private key path</label><input type="text" name="private_key_path" id="privateKeyServerPath" required></div>
                <div class="certificate-modal-actions"><button type="button" data-close-certificate-modal>Cancel</button><button type="submit">Save</button></div>
            </form>
        </div>
    </div>

    <div class="certificate-modal-backdrop" id="certbotHostnamesModal" aria-hidden="true">
        <div class="certificate-modal login-settings">
            <h2 id="certbotHostnamesTitle">Generate new using Certbot</h2>
            <p>Enter hostname(s) for this certificate</p>
            <form id="certbotHostnamesForm">
                <div id="certbotHostnameList"></div>
                <button type="button" class="md-icon-button" id="certbotAddHostname" title="Add hostname" aria-label="Add hostname">{material_icon("add")}</button>
                <div id="certbotHostnameError" class="certbot-error" style="margin-top:12px"></div>
                <div class="certificate-modal-actions"><button type="button" data-close-certificate-modal>Cancel</button><button type="submit" id="certbotStartButton">Generate</button></div>
            </form>
        </div>
    </div>

    <div class="certificate-modal-backdrop" id="certbotProgressModal" data-static="1" aria-hidden="true">
        <div class="certificate-modal login-settings">
            <div id="certbotStartingPanel" style="text-align:center">
                <div style="display:flex;justify-content:center;margin-bottom:18px">{material_spinner}</div>
                <h2>Please wait...</h2>
                <p>This may take several minutes...</p>
                <div class="certificate-modal-actions"><button type="button" id="certbotStartingCancelButton" class="certificate-delete">Cancel</button></div>
            </div>
            <div id="certbotDnsPanel" style="display:none">
                <h2>DNS authentication</h2>
                <p id="certbotChallengeProgress"></p>
                <p>Please go to your domain's DNS provider and add the following TXT record(s):</p>
                <div id="certbotChallengeList"></div>
                <div class="certbot-wait-body">
                    {material_spinner}
                    <p class="certbot-progress-note">Once every DNS record has been added and successfully propagated, the certificate will deploy automatically. Don't close this page until it has finished.</p>
                </div>
                <div class="certificate-modal-actions"><button type="button" id="certbotCancelButton" class="certificate-delete">Cancel</button></div>
            </div>
            <div id="certbotErrorPanel" style="display:none">
                <h2>Certbot failed</h2>
                <div class="certbot-error" id="certbotErrorText"></div>
                <div class="certificate-modal-actions"><button type="button" id="certbotErrorCancelButton">Cancel</button><button type="button" id="certbotRetryButton">Retry</button></div>
            </div>
            <div id="certbotSuccessPanel" style="display:none">
                <svg class="certbot-success-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"></path></svg>
                <h2 style="text-align:center">Certificate deployed successfully</h2>
                <div class="certbot-finish-options">
                    <label class="md-checkbox-container"><input type="checkbox" id="certbotEnableWeb"{web_finish_checked}><span class="md-checkmark"></span><span class="md-checkbox-text">Enable HTTPS for Web</span></label>
                    {api_finish_option}
                    {sip_finish_option}
                </div>
                <div id="certbotFinishError" class="certbot-error"></div>
                <div class="certificate-modal-actions"><button type="button" id="certbotFinishButton">Finish</button></div>
            </div>
        </div>
    </div>

    <div class="certificate-modal-backdrop" id="certbotRestartModal" data-static="1" aria-hidden="true">
        <div class="certificate-modal login-settings" style="text-align:center">
            <div style="display:flex;justify-content:center;margin-bottom:18px">{material_spinner}</div>
            <h2>Please wait...</h2>
        </div>
    </div>
    """
    script = r"""
document.addEventListener('DOMContentLoaded', function() {
    let editState = { id: '', name: '', certificatePath: '', privateKeyPath: '' };
    const choiceModal = document.getElementById('certificateChoiceModal');
    const uploadModal = document.getElementById('certificateUploadModal');
    const serverModal = document.getElementById('certificateServerModal');
    const certbotChoice = document.getElementById('chooseCertbotCertificate');
    const certbotInstallModal = document.getElementById('certbotInstallModal');
    const certbotAccountModal = document.getElementById('certbotAccountModal');
    const certbotHostnamesModal = document.getElementById('certbotHostnamesModal');
    const certbotProgressModal = document.getElementById('certbotProgressModal');
    const certbotRestartModal = document.getElementById('certbotRestartModal');
    const certbotStartingPanel = document.getElementById('certbotStartingPanel');
    const certbotDnsPanel = document.getElementById('certbotDnsPanel');
    const certbotErrorPanel = document.getElementById('certbotErrorPanel');
    const certbotSuccessPanel = document.getElementById('certbotSuccessPanel');
    let certbotJobId = '';
    let renewCertificateId = '';
    let certbotPollTimer = null;
    let certbotPollFailures = 0;
    let lastCertbotStatusMessage = '';
    let lastCertbotDnsObservations = '';
    let certbotAvailable = certbotChoice && certbotChoice.dataset.available === '1';
    let certbotAccountReady = certbotChoice && certbotChoice.dataset.accountReady === '1';
    let pendingCertbotFlow = { hostnames: [], certificateId: '' };
    const materialDeleteIcon = '<svg class="md-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM8 9h8v10H8V9zm7.5-5-1-1h-5l-1 1H5v2h14V4z"></path></svg>';
    const materialCopyIcon = '<svg class="md-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"></path></svg>';
    function closeModals() {
        document.querySelectorAll('.certificate-modal-backdrop').forEach(modal => {
            modal.classList.remove('active');
            modal.setAttribute('aria-hidden', 'true');
        });
    }
    function openModal(modal) {
        closeModals();
        modal.classList.add('active');
        modal.setAttribute('aria-hidden', 'false');
    }
    function populate(modal) {
        modal.querySelectorAll('.certificate-edit-id').forEach(input => { input.value = editState.id; });
        modal.querySelectorAll('.certificate-edit-name').forEach(input => { input.value = editState.name; });
    }
    function openChoice(state) {
        editState = state;
        document.getElementById('certificateChoiceTitle').innerText = state.id ? 'Update certificate' : 'Add certificate';
        if (certbotChoice) certbotChoice.style.display = state.id ? 'none' : '';
        openModal(choiceModal);
    }
    document.getElementById('newCertificateButton').addEventListener('click', function() {
        openChoice({ id: '', name: '', certificatePath: '', privateKeyPath: '' });
    });
    document.querySelectorAll('.certificate-update').forEach(button => {
        button.addEventListener('click', function() {
            openChoice({ id: this.dataset.id, name: this.dataset.name, certificatePath: this.dataset.certificatePath, privateKeyPath: this.dataset.privateKeyPath });
        });
    });
    document.getElementById('chooseUploadCertificate').addEventListener('click', function() {
        populate(uploadModal);
        openModal(uploadModal);
    });
    document.getElementById('chooseExistingCertificate').addEventListener('click', function() {
        populate(serverModal);
        document.getElementById('certificateServerPath').value = editState.certificatePath;
        document.getElementById('privateKeyServerPath').value = editState.privateKeyPath;
        openModal(serverModal);
    });
    function addHostname(value) {
        const list = document.getElementById('certbotHostnameList');
        const row = document.createElement('div');
        row.className = 'certbot-hostname-row';
        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'certbot-hostname';
        input.placeholder = 'ops.example.com';
        input.autocomplete = 'off';
        input.value = value || '';
        input.required = true;
        const remove = document.createElement('button');
        remove.type = 'button';
        remove.className = 'md-icon-button certbot-remove-hostname';
        remove.innerHTML = materialDeleteIcon;
        remove.setAttribute('aria-label', 'Remove hostname');
        remove.title = 'Remove hostname';
        remove.addEventListener('click', function() {
            if (list.children.length > 1) row.remove();
            else input.value = '';
        });
        row.appendChild(input);
        row.appendChild(remove);
        list.appendChild(row);
        input.focus();
    }
    function openCertbotHostnames(hostnames, certificateId) {
        renewCertificateId = certificateId || '';
        const list = document.getElementById('certbotHostnameList');
        list.innerHTML = '';
        const values = Array.isArray(hostnames) && hostnames.length ? hostnames : [''];
        values.forEach(hostname => addHostname(hostname));
        document.getElementById('certbotHostnamesTitle').innerText = renewCertificateId ? 'Renew certificate using Certbot' : 'Generate new using Certbot';
        document.getElementById('certbotStartButton').innerText = renewCertificateId ? 'Renew' : 'Generate';
        document.getElementById('certbotHostnameError').innerText = '';
        openModal(certbotHostnamesModal);
    }
    function beginCertbotFlow(hostnames, certificateId) {
        pendingCertbotFlow = { hostnames: Array.isArray(hostnames) ? hostnames : [], certificateId: certificateId || '' };
        if (!certbotAvailable) {
            openModal(certbotInstallModal);
            return;
        }
        if (!certbotAccountReady) {
            document.getElementById('certbotAccountError').innerText = '';
            openModal(certbotAccountModal);
            document.getElementById('certbotAccountEmail').focus();
            return;
        }
        openCertbotHostnames(pendingCertbotFlow.hostnames, pendingCertbotFlow.certificateId);
    }
    if (certbotChoice) {
        certbotChoice.addEventListener('click', function() {
            beginCertbotFlow([], '');
        });
        document.getElementById('certbotAddHostname').addEventListener('click', function() { addHostname(''); });
    }
    document.querySelectorAll('.certificate-certbot-renew').forEach(button => {
        button.addEventListener('click', function() {
            let domains = [];
            try { domains = JSON.parse(this.dataset.domains || '[]'); } catch (_error) {}
            beginCertbotFlow(domains, this.dataset.id);
        });
    });
    document.querySelectorAll('[data-close-certificate-modal]').forEach(button => button.addEventListener('click', closeModals));
    document.querySelectorAll('.certificate-modal-backdrop').forEach(modal => modal.addEventListener('click', function(event) {
        if (event.target === modal && !modal.dataset.static) closeModals();
    }));

    async function certbotRequest(values) {
        const body = new FormData();
        Object.keys(values).forEach(key => {
            const value = values[key];
            if (Array.isArray(value)) value.forEach(item => body.append(key, item));
            else if (value !== undefined && value !== null) body.append(key, value);
        });
        let response;
        try {
            response = await fetch('/admin/settings/certificates', {
                method: 'POST',
                body: body,
                credentials: 'same-origin',
                headers: {
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
        } catch (error) {
            console.error('[Certbot] Request could not reach OpenPagingServer', error);
            throw new Error('Unable to reach OpenPagingServer. Confirm the service is running, then try again.');
        }
        const contentType = String(response.headers.get('content-type') || '').toLowerCase();
        const responseText = await response.text();
        if (response.status === 429) {
            const retryAfter = Math.max(1, Number(response.headers.get('Retry-After') || 2));
            const rateLimitError = new Error('OpenPagingServer is temporarily rate limiting requests. Retrying automatically.');
            rateLimitError.retryAfterMs = (retryAfter * 1000) + 250;
            throw rateLimitError;
        }
        if (!contentType.includes('application/json')) {
            console.error('[Certbot] Non-JSON response', response.status, response.url, responseText);
            if (response.redirected && /\/login(?:\?|$)/.test(response.url)) {
                throw new Error('Your administrator session expired. Reload the page and sign in again.');
            }
            throw new Error('OpenPagingServer returned HTTP ' + response.status + ' instead of Certbot status. Check the server log for the matching error.');
        }
        let data;
        try {
            data = JSON.parse(responseText);
        } catch (_error) {
            console.error('[Certbot] Invalid JSON response', response.status, responseText);
            throw new Error('OpenPagingServer returned invalid Certbot status data. Check the server log for the matching error.');
        }
        if (!response.ok || data.status === 'error') throw new Error(data.message || 'Certbot request failed.');
        return data;
    }

    async function certbotRequestWithRateLimitRetry(values) {
        while (true) {
            try {
                return await certbotRequest(values);
            } catch (error) {
                if (!error || !error.retryAfterMs) throw error;
                console.info('[Certbot] Rate limited; retrying in ' + error.retryAfterMs + ' ms.');
                await new Promise(resolve => window.setTimeout(resolve, error.retryAfterMs));
            }
        }
    }

    async function waitForCertbotAccountJob(jobId) {
        while (true) {
            await new Promise(resolve => window.setTimeout(resolve, 2000));
            const data = await certbotRequestWithRateLimitRetry({ action: 'certbot_account_status', account_job_id: jobId });
            const job = data.account_job || {};
            if (job.status === 'success') return;
            if (job.status === 'error') throw new Error(job.error || "Certbot could not configure the Let's Encrypt account.");
        }
    }

    document.getElementById('certbotAccountForm').addEventListener('submit', async function(event) {
        event.preventDefault();
        const errorElement = document.getElementById('certbotAccountError');
        const button = document.getElementById('certbotAccountContinue');
        const previousButtonText = button.innerText;
        errorElement.innerText = '';
        button.disabled = true;
        button.innerText = 'Working...';
        try {
            const data = await certbotRequestWithRateLimitRetry({
                action: 'certbot_register',
                email: document.getElementById('certbotAccountEmail').value.trim(),
                agree_terms: document.getElementById('certbotAgreeTerms').checked ? '1' : '',
                eff_email: document.getElementById('certbotEffEmail').checked ? '1' : ''
            });
            await waitForCertbotAccountJob(data.account_job.id);
            certbotAccountReady = true;
            certbotChoice.dataset.accountReady = '1';
            openCertbotHostnames(pendingCertbotFlow.hostnames, pendingCertbotFlow.certificateId);
        } catch (error) {
            errorElement.innerText = error && error.message ? error.message : "Unable to configure the Let's Encrypt account.";
            openModal(certbotAccountModal);
        } finally {
            button.disabled = false;
            button.innerText = previousButtonText;
        }
    });

    function stopCertbotPolling() {
        if (certbotPollTimer) window.clearTimeout(certbotPollTimer);
        certbotPollTimer = null;
    }

    function showCertbotStarting() {
        certbotStartingPanel.style.display = '';
        certbotDnsPanel.style.display = 'none';
        certbotErrorPanel.style.display = 'none';
        certbotSuccessPanel.style.display = 'none';
        openModal(certbotProgressModal);
    }

    async function copyChallengeValue(value, button) {
        try {
            await navigator.clipboard.writeText(value);
        } catch (_error) {
            const temporary = document.createElement('textarea');
            temporary.value = value;
            temporary.style.position = 'fixed';
            temporary.style.opacity = '0';
            document.body.appendChild(temporary);
            temporary.select();
            document.execCommand('copy');
            temporary.remove();
        }
        const previousTitle = button.title;
        button.title = 'Copied';
        window.setTimeout(function() { button.title = previousTitle; }, 1200);
    }

    function renderCertbotChallenges(job) {
        const challengeList = document.getElementById('certbotChallengeList');
        const challenges = Array.isArray(job.challenges) && job.challenges.length
            ? job.challenges
            : (job.dns_name && job.dns_value ? [{ dns_name: job.dns_name, dns_value: job.dns_value }] : []);
        challengeList.innerHTML = '';
        challenges.forEach(challenge => {
            const card = document.createElement('div');
            card.className = 'certbot-challenge';
            [['Name', challenge.dns_name], ['Value', challenge.dns_value]].forEach(item => {
                const row = document.createElement('div');
                row.className = 'certbot-challenge-row';
                const label = document.createElement('strong');
                label.innerText = item[0];
                const code = document.createElement('code');
                code.innerText = item[1] || '';
                const copy = document.createElement('button');
                copy.type = 'button';
                copy.className = 'md-icon-button';
                copy.innerHTML = materialCopyIcon;
                copy.title = 'Copy ' + item[0].toLowerCase();
                copy.setAttribute('aria-label', copy.title);
                copy.addEventListener('click', function() { copyChallengeValue(item[1] || '', copy); });
                row.appendChild(label);
                row.appendChild(code);
                row.appendChild(copy);
                card.appendChild(row);
            });
            challengeList.appendChild(card);
        });
        return challenges;
    }

    function showCertbotDns(job) {
        const challenges = renderCertbotChallenges(job);
        if (!challenges.length) {
            showCertbotStarting();
            return;
        }
        certbotStartingPanel.style.display = 'none';
        certbotDnsPanel.style.display = '';
        certbotErrorPanel.style.display = 'none';
        certbotSuccessPanel.style.display = 'none';
        if (job.status_message && job.status_message !== lastCertbotStatusMessage) {
            console.info('[Certbot] ' + job.status_message);
            lastCertbotStatusMessage = job.status_message;
        }
        const serializedObservations = JSON.stringify(job.external_observations || {});
        if (serializedObservations !== '{}' && serializedObservations !== lastCertbotDnsObservations) {
            console.info('[Certbot] Public DNS observations:', job.external_observations);
            lastCertbotDnsObservations = serializedObservations;
        }
        const total = Number(job.challenge_total || 1);
        document.getElementById('certbotChallengeProgress').innerText = total > 1 ? (total + ' DNS challenges') : '';
    }

    function showCertbotError(message) {
        stopCertbotPolling();
        certbotStartingPanel.style.display = 'none';
        certbotDnsPanel.style.display = 'none';
        certbotSuccessPanel.style.display = 'none';
        certbotErrorPanel.style.display = '';
        document.getElementById('certbotErrorText').innerText = message || 'Certbot failed to issue the certificate.';
        openModal(certbotProgressModal);
    }

    function showCertbotSuccess(job) {
        stopCertbotPolling();
        certbotStartingPanel.style.display = 'none';
        certbotDnsPanel.style.display = 'none';
        certbotErrorPanel.style.display = 'none';
        certbotSuccessPanel.style.display = '';
        document.getElementById('certbotFinishError').innerText = '';
        sessionStorage.setItem('ops-certbot-job', job.id);
        openModal(certbotProgressModal);
    }

    async function pollCertbotJob() {
        if (!certbotJobId) return;
        try {
            const data = await certbotRequest({ action: 'certbot_status', job_id: certbotJobId });
            certbotPollFailures = 0;
            const job = data.job || {};
            if (job.status === 'success') {
                showCertbotSuccess(job);
                return;
            }
            if (job.status === 'error') {
                showCertbotError(job.error);
                return;
            }
            if (job.status === 'cancelled') {
                stopCertbotPolling();
                sessionStorage.removeItem('ops-certbot-job');
                closeModals();
                return;
            }
            if (job.status === 'starting' || job.status === 'collecting') showCertbotStarting();
            else showCertbotDns(job);
            openModal(certbotProgressModal);
            certbotPollTimer = window.setTimeout(pollCertbotJob, 2000);
        } catch (error) {
            if (error && error.retryAfterMs) {
                certbotPollTimer = window.setTimeout(pollCertbotJob, error.retryAfterMs);
                return;
            }
            certbotPollFailures += 1;
            console.error('[Certbot] Status poll failed (' + certbotPollFailures + '/5)', error);
            if (certbotPollFailures < 5) {
                certbotPollTimer = window.setTimeout(pollCertbotJob, 3000);
                return;
            }
            showCertbotError(error && error.message ? error.message : 'Unable to read Certbot status.');
        }
    }

    async function startCertbot(hostnames) {
        showCertbotStarting();
        const data = await certbotRequest({
            action: 'certbot_start',
            hostnames: hostnames,
            renew_certificate_id: renewCertificateId
        });
        certbotJobId = data.job.id;
        certbotPollFailures = 0;
        sessionStorage.setItem('ops-certbot-job', certbotJobId);
        stopCertbotPolling();
        certbotPollTimer = window.setTimeout(pollCertbotJob, 1000);
    }

    if (certbotChoice) {
        document.getElementById('certbotHostnamesForm').addEventListener('submit', async function(event) {
            event.preventDefault();
            const hostnames = Array.from(document.querySelectorAll('.certbot-hostname')).map(input => input.value.trim()).filter(Boolean);
            const errorElement = document.getElementById('certbotHostnameError');
            const button = document.getElementById('certbotStartButton');
            errorElement.innerText = '';
            button.disabled = true;
            try {
                await startCertbot(hostnames);
            } catch (error) {
                errorElement.innerText = error && error.message ? error.message : 'Unable to start Certbot.';
                openModal(certbotHostnamesModal);
            } finally {
                button.disabled = false;
            }
        });
    }

    async function cancelCurrentCertbotJob() {
        stopCertbotPolling();
        if (certbotJobId) {
            try { await certbotRequest({ action: 'certbot_cancel', job_id: certbotJobId }); } catch (_error) {}
        }
        certbotJobId = '';
        sessionStorage.removeItem('ops-certbot-job');
        closeModals();
    }

    document.getElementById('certbotStartingCancelButton').addEventListener('click', cancelCurrentCertbotJob);
    document.getElementById('certbotCancelButton').addEventListener('click', cancelCurrentCertbotJob);
    document.getElementById('certbotErrorCancelButton').addEventListener('click', cancelCurrentCertbotJob);
    document.getElementById('certbotRetryButton').addEventListener('click', async function() {
        this.disabled = true;
        showCertbotStarting();
        try {
            const data = await certbotRequest({ action: 'certbot_retry', job_id: certbotJobId });
            certbotJobId = data.job.id;
            certbotPollFailures = 0;
            sessionStorage.setItem('ops-certbot-job', certbotJobId);
            stopCertbotPolling();
            certbotPollTimer = window.setTimeout(pollCertbotJob, 1000);
        } catch (error) {
            showCertbotError(error && error.message ? error.message : 'Unable to retry Certbot.');
        } finally {
            this.disabled = false;
        }
    });

    document.getElementById('certbotFinishButton').addEventListener('click', async function() {
        const finishError = document.getElementById('certbotFinishError');
        finishError.innerText = '';
        this.disabled = true;
        try {
            const apiToggle = document.getElementById('certbotEnableApi');
            const sipToggle = document.getElementById('certbotEnableSip');
            const data = await certbotRequest({
                action: 'certbot_finish',
                job_id: certbotJobId,
                enable_web_https: document.getElementById('certbotEnableWeb').checked ? '1' : '',
                enable_api_https: apiToggle && apiToggle.checked ? '1' : '',
                enable_sip_tls: sipToggle && sipToggle.checked ? '1' : ''
            });
            sessionStorage.removeItem('ops-certbot-job');
            if (data.restart_scheduled) {
                openModal(certbotRestartModal);
                window.setTimeout(function() { window.location.reload(); }, 30000);
            } else {
                window.location.reload();
            }
        } catch (error) {
            finishError.innerText = error && error.message ? error.message : 'Unable to finish certificate setup.';
        } finally {
            this.disabled = false;
        }
    });

    const savedCertbotJob = sessionStorage.getItem('ops-certbot-job');
    if (savedCertbotJob && certbotChoice) {
        certbotJobId = savedCertbotJob;
        pollCertbotJob();
    }
    function updateCountdowns() {
        const now = Math.floor(Date.now() / 1000);
        document.querySelectorAll('.certificate-countdown').forEach(element => {
            const expires = Number(element.dataset.expires || 0);
            let remaining = Math.abs(expires - now);
            const days = Math.floor(remaining / 86400); remaining -= days * 86400;
            const hours = Math.floor(remaining / 3600); remaining -= hours * 3600;
            const minutes = Math.floor(remaining / 60);
            const parts = [];
            if (days) parts.push(days + ' day' + (days === 1 ? '' : 's'));
            if (hours && parts.length < 2) parts.push(hours + ' hour' + (hours === 1 ? '' : 's'));
            if (!days && minutes && parts.length < 2) parts.push(minutes + ' minute' + (minutes === 1 ? '' : 's'));
            const text = parts.join(', ') || 'less than one minute';
            element.innerText = expires <= now ? text + ' ago' : 'in ' + text;
        });
    }
    updateCountdowns();
    window.setInterval(updateCountdowns, 60000);
});
"""
    return settings_page("Certificates", legacy_user_context(user), "certificates", body, script)


def handle_request():
    action = str(request.form.get("action") or "").strip().lower() if request.method == "POST" else ""
    certbot_request = request.method == "POST" and action.startswith("certbot_")
    try:
        user = require_admin()
    except HTTPException as exc:
        if certbot_request:
            return jsonify(status="error", message="Administrator access is required. Reload the page and sign in again."), int(exc.code or 403)
        raise
    if not isinstance(user, dict):
        if certbot_request:
            return jsonify(status="error", message="Your administrator session expired. Reload the page and sign in again."), 401
        return user
    if demo_mode_enabled():
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(status="error", message="Demo Mode is enabled."), 403
        return redirect("/dashboard?demomodal=settings")
    try:
        ensure_certificate_schema()
    except Exception as exc:
        if certbot_request:
            app.logger.exception("Unable to prepare certificate storage for a Certbot request")
            return jsonify(status="error", message=str(exc) or "Unable to prepare certificate storage."), 500
        raise
    if request.method == "POST":
        if action.startswith("certbot_"):
            try:
                if action == "certbot_register":
                    account_job = start_certbot_account_job(
                        request.form.get("email"),
                        str(request.form.get("agree_terms") or "") == "1",
                        str(request.form.get("eff_email") or "") == "1",
                    )
                    return jsonify(status="success", account_job=account_job)
                if action == "certbot_account_status":
                    account_job = get_certbot_account_job(request.form.get("account_job_id"))
                    if not account_job:
                        raise ValueError("The Certbot account setup is no longer available. Click Continue to try again.")
                    return jsonify(status="success", account_job=account_job)
                if action == "certbot_start":
                    renew_certificate_id = str(request.form.get("renew_certificate_id") or "").strip()
                    renew_record = certificate_record(renew_certificate_id) if renew_certificate_id else None
                    if renew_certificate_id and (not renew_record or not renew_record.get("certbot_name")):
                        raise ValueError("The Certbot-managed certificate was not found.")
                    job = start_certbot_job(
                        request.form.getlist("hostnames"),
                        existing_certbot_name=renew_record.get("certbot_name") if renew_record else None,
                        renew_certificate_id=renew_record.get("id") if renew_record else None,
                    )
                else:
                    job_id = str(request.form.get("job_id") or "").strip()
                    job = get_certbot_job(job_id)
                    if not job:
                        raise ValueError("The Certbot job is no longer available.")
                    if action == "certbot_cancel":
                        cancel_certbot_job(job_id)
                        return jsonify(status="success")
                    if action == "certbot_retry":
                        if job.get("status") == "success":
                            job = register_certbot_job(job)
                        else:
                            cancel_certbot_job(job_id)
                            job = start_certbot_job(
                                job.get("hostnames") or [],
                                existing_certbot_name=job.get("certbot_name") if job.get("renew_certificate_id") else None,
                                renew_certificate_id=job.get("renew_certificate_id"),
                            )
                    elif action == "certbot_status":
                        if job.get("status") == "success":
                            job = register_certbot_job(job)
                    elif action == "certbot_finish":
                        if job.get("status") != "success":
                            raise ValueError("Certbot has not finished deploying the certificate.")
                        job = register_certbot_job(job)
                        restart_scheduled = finish_certbot_job(job, settings())
                        return jsonify(status="success", restart_scheduled=restart_scheduled)
                    else:
                        raise ValueError("Unknown Certbot action.")
                return jsonify(status="success", job=job)
            except Exception as exc:
                expected = isinstance(exc, (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, pymysql.MySQLError))
                if not expected:
                    app.logger.exception("Unexpected failure while handling Certbot action %s", action)
                return jsonify(status="error", message=str(exc) or "Certbot request failed."), 400 if expected else 500
        certificate_id = str(request.form.get("certificate_id") or "").strip()
        record = certificate_record(certificate_id) if certificate_id else None
        try:
            if certificate_id and not record:
                raise ValueError("Certificate was not found.")
            if action in {"upload", "server"}:
                message = save_certificate_record(action, record)
            elif action == "delete":
                if not record:
                    raise ValueError("Certificate was not found.")
                usage = certificate_usage(record["id"])
                if usage:
                    raise ValueError("Certificate is still used by: " + ", ".join(service.upper() for service in usage) + ".")
                if record.get("certbot_name"):
                    delete_certbot_certificate(record["certbot_name"])
                execute("DELETE FROM certificates WHERE id=%s", (record["id"],))
                remove_managed_files(record)
                message = "Certificate deleted."
            else:
                raise ValueError("Unknown certificate action.")
            return redirect("/admin/settings/certificates?" + urlencode({"message": message}))
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, pymysql.MySQLError) as exc:
            return render_page(user, error=str(exc))
    return render_page(user, message=request.args.get("message", ""))
