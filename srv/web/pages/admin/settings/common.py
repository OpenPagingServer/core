
from srv.web.app import demo_mode_enabled, h, legacy_page

SETTINGS_STYLE = r"""
body, html { margin:0; padding:0; font-family:"Tahoma",sans-serif; font-weight:300; background-color:#FFF; height:100%; }
strong { font-weight:700; }
#sidebar { width:220px; background-color:var(--ops-accent); color:#FFF; height:100vh; position:fixed; top:0; left:0; display:flex; flex-direction:column; box-shadow:2px 0 8px rgba(0,0,0,0.2); transition:transform 0.3s ease; z-index:1200; }
@media (max-width:767px){ #sidebar{ transform:translateX(-100%); } #sidebar.open{ transform:translateX(0); } }
#sidebar h2 { text-align:center; padding:20px 0; margin:0; font-weight:500; background-color:var(--ops-accent-hover); font-size:1.2em; color:#FFF; }
#sidebar a,.logout-btn,.logout-btn-mobile,.admin-only{ color:#FFF; padding:12px 20px; display:block; border-bottom:1px solid rgba(255,255,255,0.1); text-decoration:none; transition:background 0.3s; font-size:0.9em; text-align:left; box-sizing:border-box; }
#sidebar a i,.logout-btn i,.logout-btn-mobile i,.admin-only i { margin-right:8px; width:20px; }
#sidebar a:hover,#sidebar a.active{ background-color:var(--ops-accent-hover); }
.logout-btn{ background-color:#C62828; border:none; cursor:pointer; margin-top:auto; transition:background-color 0.3s; }
.logout-btn:hover{ background-color:#B71C1C; }
.logout-btn:active{ background-color:#A51B1B; }
.logout-btn-mobile{ background-color:#C62828; border:none; cursor:pointer; transition:background-color 0.3s; display:none; }
.logout-btn-mobile:hover{ background-color:#B71C1C; }
@media(max-width:767px){ .logout-btn{ display:none; } .logout-btn-mobile{ display:block; } }
#mobile-header{ display:flex; background-color:var(--ops-accent-hover); color:#FFF; padding:calc(12px + env(safe-area-inset-top)) 16px 12px 16px; align-items:center; justify-content:space-between; position:fixed; top:0; left:0; right:0; z-index:1100; }
#mobile-header h2{ margin:0; font-size:1.1em; font-weight:400; color:#FFF; }
#mobile-header .hamburger{ font-size:1.5em; cursor:pointer; }
#overlay{ display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.3); z-index:900; }
#overlay.active{ display:block; }
#content{ margin-left:220px; padding:24px; height:100vh; overflow-y:auto; width:calc(100% - 220px); box-sizing:border-box; transition:margin-left 0.3s ease; }
@media(max-width:767px){ #content{ margin-left:0; width:100%; padding-top:70px; } }
#content h2{ color:var(--ops-accent); margin-bottom:16px; font-weight:400; }
#content h1{ font-weight:400; }
.info-card{ background:#FFF; padding:16px; border:1px solid #EEE; border-radius:8px; box-shadow:0 2px 4px rgba(0,0,0,0.1); margin-bottom:16px; }
.info-row { display:flex; justify-content:space-between; padding:10px 0; border-bottom:1px solid #f0f0f0; align-items: center; }
.info-row:last-child { border-bottom:none; }
.info-label { font-weight:500; color:#555; }
.info-description { display:block; margin-top:4px; color:#777; font-size:0.88em; font-weight:300; line-height:1.35; }
.info-description a { color:var(--ops-accent); text-decoration:none; }
.info-description a:hover { text-decoration:underline; }
.tabs-container { margin-bottom: 20px; border-bottom: 1px solid #DDD; }
.tabs-desktop { display: flex; gap: 10px; }
.tab-link { padding: 10px 20px; cursor: pointer; border: 1px solid transparent; border-bottom: none; border-radius: 5px 5px 0 0; background: #f5f5f5; color: #555; transition: 0.3s; text-decoration: none; }
.tab-link.active { background: var(--ops-accent); color: #FFF; border-color: var(--ops-accent); }
.tabs-mobile { display: none; width: 100%; padding: 10px; border-radius: 5px; border: 1px solid #CCC; margin-bottom: 15px; font-size: 16px; }
.tab-content { display: none; }
.tab-content.active { display: block; }
.switch { position: relative; display: inline-block; width: 36px; height: 14px; }
.switch input { opacity: 0; width: 0; height: 0; }
.slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; border-radius: 14px; }
.slider:before { position: absolute; content: ""; height: 20px; width: 20px; left: -2px; bottom: -3px; background-color: white; transition: .4s; border-radius: 50%; box-shadow: 0 2px 4px rgba(0,0,0,0.2); }
input:checked + .slider { background-color: #90caf9; }
input:checked + .slider:before { transform: translateX(20px); background-color: var(--ops-accent); }
.login-settings input[type="text"], .login-settings input[type="password"], .login-settings input[type="number"], .login-settings select, .login-settings textarea { width:100%; padding:10px; border-radius:6px; border:1px solid #CCC; font-family:inherit; font-size:14px; box-sizing:border-box; }
.login-settings textarea { resize:vertical; min-height:80px; }
.login-settings input:disabled, .login-settings select:disabled, .login-settings textarea:disabled { background:rgba(0,0,0,0.05); color:#999; cursor:not-allowed; }
.md-checkbox-container { display:flex; align-items:center; position:relative; cursor:pointer; font-size:14px; font-weight:500; color:#555; user-select:none; gap:12px; }
.md-checkbox-container input { position:absolute; opacity:0; cursor:pointer; height:0; width:0; }
.md-checkmark { position:relative; display:inline-block; flex:0 0 auto; height:20px; width:20px; background:#FFF; border:2px solid #5f6368; border-radius:2px; transition:all 0.2s; }
.md-checkbox-container:hover input ~ .md-checkmark { border-color:#202124; }
.md-checkbox-container input:checked ~ .md-checkmark { background:var(--ops-accent); border-color:var(--ops-accent); }
.md-checkmark:after { content:""; position:absolute; display:none; left:6px; top:2px; width:4px; height:10px; border:solid #FFF; border-width:0 2px 2px 0; transform:rotate(45deg); }
.md-checkbox-container input:checked ~ .md-checkmark:after { display:block; }
.md-checkbox-text { flex:1 1 auto; min-width:0; }
.login-settings button { background:var(--ops-accent); color:#FFF; border:none; padding:10px 16px; border-radius:6px; font-size:14px; cursor:pointer; }
.login-settings button:hover { background:var(--ops-accent-hover); }
.login-settings h4 { margin: 0 0 4px 0; font-weight: 500; font-size: 1.1em; }
.login-settings p { margin: 0 0 12px 0; font-size: 0.9em; color: #666; }
.port-error-text { color: #F44336; font-size: 0.8em; margin-top: 4px; display: none; }
.invalid-port { border-color: #F44336 !important; background-color: rgba(244, 67, 54, 0.05) !important; }
.server-image { width:300px; height:auto; margin:0 auto 24px auto; display:block; border-radius:12px; }
.save-status { margin-left: 10px; font-size: 0.85em; transition: opacity 0.5s; }
@media(max-width:767px){ .tabs-desktop { display: none; } .tabs-mobile { display: block; } }
@media(min-width:768px){ #mobile-header{ display:none; } }
@media(prefers-color-scheme:dark){
body,html{ background-color:#121212; color:#E0E0E0; }
#sidebar{ background-color:#424242; }
#sidebar h2{ background-color:#303030; color:#FFF; }
#sidebar a,.logout-btn,.logout-btn-mobile,.admin-only{ color:#E0E0E0; }
#sidebar a.active,#sidebar a:hover{ background-color:#505050; }
#mobile-header{ background-color:#424242; }
#mobile-header h2{ color:#FFF; }
#content{ background-color:#121212; }
.info-card{ border:1px solid #333; background-color:#1E1E1E; }
h2,h3,h4{ color:#BB86FC; }
.info-label { color:#BBB; }
.info-description { color:#999; }
.info-description a { color:#BB86FC; }
.info-row { border-bottom:1px solid #333; }
.tabs-container { border-bottom-color: #333; }
.tab-link { background: #333; color: #BBB; }
.tab-link.active { background: #BB86FC; color: #000; }
.tabs-mobile { background: #1E1E1E; color: #E0E0E0; border-color: #444; }
input:checked + .slider { background-color: #3d2b52; }
input:checked + .slider:before { background-color: #BB86FC; }
.login-settings input[type="text"], .login-settings input[type="password"], .login-settings input[type="number"], .login-settings select, .login-settings textarea { background:#1E1E1E; border:1px solid #444; color:#E0E0E0; }
.login-settings input:disabled, .login-settings select:disabled, .login-settings textarea:disabled { background:#2A2A2A; color:#777; }
.md-checkbox-container { color:#BBB; }
.md-checkmark { border-color:#9AA0A6; background:#1E1E1E; }
.md-checkbox-container:hover input ~ .md-checkmark { border-color:#E8EAED; }
.md-checkbox-container input:checked ~ .md-checkmark { background:#8AB4F8; border-color:#8AB4F8; }
.md-checkmark:after { border-color:#1E1E1E; }
.login-settings button { background:#BB86FC; color:#000; }
.login-settings button:hover { background:#A370F7; }
.login-settings p { color: #AAA; }
.port-error-text { color: #ff5252; }
.invalid-port { border-color: #ff5252 !important; }
}
"""

SETTINGS_SCRIPT = r"""
function postSettings(formId, buttonId, statusId, successText, reloadAfter) {
    const button = document.getElementById(buttonId);
    const status = document.getElementById(statusId);
    if (!button) return;
    button.addEventListener('click', function() {
        if (window.openDemoModePopup && window.location.pathname.indexOf('/admin/settings/') === 0 && document.querySelector('[data-demo-mode="1"]')) {
            openDemoModePopup('settings');
            return;
        }
        const formData = new FormData(document.getElementById(formId));
        button.disabled = true;
        status.innerText = "Saving...";
        status.style.color = "inherit";
        fetch(window.location.href, {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                status.innerText = successText;
                status.style.color = "#4CAF50";
                if (reloadAfter) setTimeout(() => { location.reload(); }, 1000);
            } else {
                status.innerText = data.message || "Error saving settings.";
                status.style.color = "#F44336";
            }
        })
        .catch(() => {
            status.innerText = "Connection error.";
            status.style.color = "#F44336";
        })
        .finally(() => {
            button.disabled = false;
            setTimeout(() => { status.innerText = ""; }, 3000);
        });
    });
}
"""


def settings_tabs(active):
    demo = demo_mode_enabled()
    items = [
        ("general", "General", "/admin/settings/general"),
        ("login", "Login", "/admin/settings/login"),
        ("sip", "SIP", "/admin/settings/sip"),
        ("web", "Web", "/admin/settings/web"),
        ("api", "API", "/admin/settings/api"),
        ("certificates", "Certificates", "/admin/settings/certificates"),
        ("branding", "Branding", "/admin/settings/branding"),
        ("advanced", "Advanced", "/admin/settings/advanced"),
        ("about", "About", "/admin/settings/about"),
    ]
    links = []
    for key, label, url in items:
        protected = demo and key == "certificates"
        href = "/dashboard?demomodal=settings" if protected else url
        active_class = " active" if key == active else ""
        onclick = ' onclick="if(window.openDemoModePopup){openDemoModePopup(\'settings\');return false;}"' if protected else ""
        links.append(f'<a href="{h(href)}" class="tab-link{active_class}"{onclick}>{h(label)}</a>')
    links = "".join(links)
    options = "".join(
        f'<option value="{h("/dashboard?demomodal=settings" if demo and key == "certificates" else url)}"{" selected" if key == active else ""}>{h(label)}</option>'
        for key, label, url in items
    )
    return f"""    <h1>Settings</h1>
    <div class="tabs-container">
        <div class="tabs-desktop">{links}</div>
        <select class="tabs-mobile" onchange="window.location.href=this.value">{options}</select>
    </div>"""


def settings_page(title, ctx, active, body, extra_script=""):
    demo_attr = ' data-demo-mode="1"' if demo_mode_enabled() else ""
    wrapped = f'<div{demo_attr}>{settings_tabs(active) + body}</div>'
    return legacy_page(title, ctx, "settings", SETTINGS_STYLE, wrapped, SETTINGS_SCRIPT + extra_script)
