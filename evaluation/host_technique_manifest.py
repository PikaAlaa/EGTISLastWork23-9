"""Build the per-file expected-technique manifest for EVTX-ATTACK-SAMPLES (design host-engine-v1 §3.2, §4.3).

Labels come only from each sample's path (folder and file name) through the fixed keyword
table below, plus ATT&CK ids written in a file name. No sample is opened or parsed, and the
repository's event-level CSV is not used. The repository's published per-technique mapping
is reachable only through a URL shortener and was not used. Every technique is resolved in
the pinned ATT&CK v20.0 catalogue (revoked ids follow `revoked-by`). A sample whose name
matches no keyword is `excluded_undetermined` and counted. Files with identical content are
one sample. Split: last hex digit of the content SHA-256 even -> development, odd -> report.

Usage: python evaluation/host_technique_manifest.py   (writes the report-directory manifest)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'evaluation/reports/2026-11-host-v1/technique_manifest.json'
LOCK = ROOT / 'data/evtx-attack-samples-lock.json'

# (keyword found in the normalised file name, ATT&CK v20.0 techniques it names). Normalised
# names are lower case with every run of non-alphanumeric characters replaced by "_", and
# are padded with "_" so keywords can anchor on word edges. Written before any measurement.
KEYWORDS = [
    # Logging and defences
    ('_log_cleared_', ['T1685.005']),
    ('_eventlog_service_crashed_', ['T1685.001']),
    ('_wineventlogsvc_crash_', ['T1685.001']),
    ('_eventlog_svc_crash_', ['T1685.001']),
    ('_remote_eventlog_svc_access_', ['T1685.001']),
    ('_psscriptblocklogging_disabled_', ['T1685.001']),
    ('_clm_disabled_', ['T1685']),
    ('_uac_disabled_', ['T1548.002']),
    ('uacbypass', ['T1548.002']),
    ('_uac_bypass', ['T1548.002']),
    ('bypassuac', ['T1548.002']),
    ('_uacme_', ['T1548.002']),
    ('timestomp', ['T1070.006']),
    ('sideloading', ['T1574.001']),
    ('dllhijack', ['T1574.001']),
    ('_dll_hijack_', ['T1574.001']),
    ('hollowing', ['T1055.012']),
    ('herpaderping', ['T1055']),
    ('_codeinj_', ['T1055']),
    ('_injection_', ['T1055']),
    ('reflectivepeinjection', ['T1055']),
    ('_migrate_to_', ['T1055']),
    ('_psinject_', ['T1055']),
    ('_ppid_spoofing_', ['T1134.004']),
    ('_masquerading_', ['T1036']),
    ('_renamed_', ['T1036.003']),
    ('_hiding_files_via_attrib_', ['T1564.001']),
    ('_dse_bypass_', ['T1553.006']),
    ('_testsigning_on_', ['T1553.006']),
    ('_portforward_netsh_', ['T1090.001']),
    ('_rdp_settings_tampering_', ['T1112']),
    ('_xp_cmdshell_', ['T1505.001']),
    ('xpcmdshell', ['T1505.001']),
    ('_antiforensics_', ['T1070']),
    ('_webshell_', ['T1505.003']),
    # Credential access
    ('_ca_dcsync_', ['T1003.006']),
    ('_dcsync_right_', ['T1098']),
    ('_powerview_', ['T1059.001']),
    ('_ntdsutil_', ['T1003.003']),
    ('_hashdump_', ['T1003.002']),
    ('_remote_sam_registry_access_', ['T1003.002']),
    ('_lsass_dump_', ['T1003.001']),
    ('_lsass_access_', ['T1003.001']),
    ('_lsass_memdump_', ['T1003.001']),
    ('_lsass_mimikatz_', ['T1003.001']),
    ('_lsass_with_different_pid_', ['T1003.001']),
    ('minidumpwritedump_lsass', ['T1003.001']),
    ('lsasssilentprocessexit', ['T1003.001']),
    ('_dumpert_', ['T1003.001']),
    ('_comsvcs_minidump_', ['T1003.001']),
    ('_ppldump_', ['T1003.001']),
    ('_malseclogon_', ['T1003.001']),
    ('_sekurlsa_logonpasswords_', ['T1003.001']),
    ('_invoke_mimikatz_', ['T1003.001']),
    ('_memssp_', ['T1547.005']),
    ('keepass', ['T1555.005']),
    ('_keefarce_', ['T1555.005']),
    ('_chrome_firefox_opera_', ['T1555.003']),
    ('_teamviewer_dumper_', ['T1555']),
    ('_iis_pwd_and_config_discovery_', ['T1552.001']),
    ('_pwd_spray_', ['T1110.003']),
    ('_multiple_failed_logon_', ['T1110.001']),
    ('_phish_windows_credentials_', ['T1056.002']),
    ('_keylogger_', ['T1056.001']),
    ('zerologon', ['T1210']),
    ('_cve_2020_1472_', ['T1210']),
    ('_bluekeep_', ['T1210']),
    ('petipotam', ['T1187']),
    ('petitpotam', ['T1187']),
    ('spoolsample', ['T1187']),
    ('_privexchange_', ['T1187']),
    ('_dsrm_password_change_', ['T1098']),
    ('_acl_forcepwd_spnadd_', ['T1098']),
    ('_local_admin_password_changed_', ['T1098']),
    ('_remote_pwd_reset_', ['T1098']),
    # Discovery
    ('_local_groups_enumeration_', ['T1069.001']),
    ('_local_user_or_group_', ['T1069.001', 'T1087.001']),
    ('_net_group_domain_admins_', ['T1069.002']),
    ('_bloodhound_', ['T1087.002']),
    ('_enum_shares_', ['T1135']),
    ('_psloggedon_', ['T1033']),
    ('_netsessionenum_', ['T1049']),
    ('_process_listing_', ['T1057']),
    ('_remote_system_namedpipes_', ['T1018']),
    # Execution and proxy execution
    ('mshta', ['T1218.005']),
    ('rundll32', ['T1218.011']),
    ('regsvr32', ['T1218.010']),
    ('_scrobj_', ['T1218.010']),
    ('_sct_', ['T1218.010']),
    ('msxsl', ['T1220']),
    ('_xsl_', ['T1220']),
    ('compiledhtml', ['T1218.001']),
    ('_cpl_', ['T1218.002']),
    ('controlpanelapplet', ['T1218.002']),
    ('_pcalua_', ['T1202']),
    ('_exec_sysmon_1_ftp_', ['T1202']),
    ('_explorer_exec_', ['T1202']),
    ('_vshadow_exec_', ['T1202']),
    ('_msipackage_', ['T1218.007']),
    ('_rogue_msi_', ['T1218.007']),
    ('jscript', ['T1059.007']),
    ('_vbs_', ['T1059.005']),
    ('_revshell_cmd_', ['T1059.003']),
    ('_visual_studio_prebuild_event_', ['T1127']),
    ('_driveby_', ['T1189']),
    ('_maldoc_', ['T1204.002']),
    ('_wuauclt_lolbas_', ['T1218']),
    ('wmic', ['T1047']),
    ('_wmi_', ['T1047']),
    ('wmiexec', ['T1047']),
    ('_commandlineeventconsumer_', ['T1546.003']),
    ('wmighost', ['T1546.003']),
    ('_powershell_4104_', ['T1059.001']),
    ('_ps_4104_', ['T1059.001']),
    ('_ps_800_', ['T1059.001']),
    ('_scriptblocklog_', ['T1059.001']),
    ('_mimikatz_powershell_', ['T1059.001']),
    ('_invoke_', ['T1059.001']),
    ('_get_keepassdatabasekey_', ['T1059.001']),
    ('_unmanagedpowershell_', ['T1059.001']),
    ('_powercat_', ['T1059.001']),
    ('_remote_task_src_powershell_', ['T1059.001']),
    ('bitsadmin', ['T1197']),
    ('_bits_', ['T1197']),
    ('_bitsjob_', ['T1197']),
    ('downldr', ['T1105']),
    ('_hosted_github_', ['T1105']),
    # Persistence
    ('_run_key_', ['T1547.001']),
    ('_runpersist_', ['T1547.001']),
    ('_run_keyvalue_', ['T1547.001']),
    ('_startup_folder_', ['T1547.001']),
    ('_usershellstartup_', ['T1547.001']),
    ('_lateral_movement_startup_', ['T1547.001']),
    ('_winlogon_shell_', ['T1547.004']),
    ('_accessibility_features_', ['T1546.008']),
    ('_silentprocessexit_imagehijack_', ['T1546.012']),
    ('_shime_', ['T1546.011']),
    ('_appfix_', ['T1546.011']),
    ('comhijack', ['T1546.015']),
    ('_pendinggpo_', ['T1484.001']),
    ('_dcshadow_', ['T1207']),
    ('_hidden_local_account_', ['T1136.001']),
    ('_local_account_creation_', ['T1136.001']),
    ('_fake_computeraccount_', ['T1136']),
    ('_added_to_admins_', ['T1098.007']),
    ('_added_admingroup_', ['T1098.007']),
    ('_persist_as_service_', ['T1543.003']),
    ('_7045_', ['T1543.003']),
    ('_unquoted_svc_', ['T1574.009']),
    # Scheduled tasks
    ('_scheduled_task_', ['T1053.005']),
    ('_scheduledtask_', ['T1053.005']),
    ('schtask', ['T1053.005']),
    ('schedtask', ['T1053.005']),
    ('_4698_', ['T1053.005']),
    ('_remote_task_', ['T1053.005']),
    # Lateral movement and remote services
    ('psexec', ['T1569.002']),
    ('_remcom_', ['T1569.002']),
    ('_remote_service', ['T1569.002']),
    ('_dcom_', ['T1021.003']),
    ('_mmc20_', ['T1021.003']),
    ('shellbrowserwind', ['T1021.003']),
    ('_docmexec_', ['T1021.003']),
    ('_winrm_exec_', ['T1021.006']),
    ('_winrm_target_', ['T1021.006']),
    ('_powershellremoting_', ['T1021.006']),
    ('_remotepowershell_', ['T1021.006']),
    ('_remote_filecopy_', ['T1570']),
    ('_remote_file_copy_', ['T1570']),
    ('_smbmap_upload_', ['T1570']),
    ('_pass_the_hash_', ['T1550.002']),
    ('_pth_', ['T1550.002']),
    ('_rdp_tunnel', ['T1021.001']),
    ('_rdp_tun_', ['T1021.001']),
    ('_rdp_smb_tunneling_', ['T1021.001']),
    ('_rdp_client_', ['T1021.001']),
    ('sharprdp', ['T1021.001']),
    ('rdpsharp', ['T1021.001']),
    ('_tsclient_', ['T1021.001']),
    ('_tunnel', ['T1572']),
    ('_rdp_tun_', ['T1572']),
    # Privilege escalation and tokens
    ('potato', ['T1134.001']),
    ('_roguewinrm_', ['T1134.001']),
    ('_seimpersonate', ['T1134.001']),
    ('_imperson_', ['T1134.001']),
    ('_impersonateuser_', ['T1134.001']),
    ('namedpipeimpersonation', ['T1134.001']),
    ('_tokenduplication_', ['T1134.001']),
    ('_token_manip_', ['T1134']),
    ('createprocessasuser', ['T1134.002']),
    ('_runas_', ['T1134.002']),
    ('_sidhistory_', ['T1134.005']),
    ('_cve_2020_0796_', ['T1068']),
    ('_cve_2020_1313_', ['T1068']),
    ('_cve_2020_1377_', ['T1068']),
    ('_cve_20201030_', ['T1068']),
    ('_spoolfool_', ['T1068']),
    ('_cve_2021_42287_', ['T1068']),
]
_EXPLICIT = re.compile(r'_t(\d{4})(?:_(\d{3}))?_')


def normalise(path: str) -> str:
    return '_' + re.sub(r'[^a-z0-9]+', '_', path.rsplit('/', 1)[-1].rsplit('.', 1)[0].lower()).strip('_') + '_'


def label(path: str, resolve) -> tuple[list[str], list[dict]]:
    """Techniques named by a sample's file name, and which keyword gave each one."""
    name, techniques, sources = normalise(path), set(), []
    for match in _EXPLICIT.finditer(name):
        raw = 'T' + match.group(1) + ('.' + match.group(2) if match.group(2) else '')
        resolved = resolve(raw)
        if resolved:
            techniques.add(resolved)
            sources.append({'keyword': f'explicit id {raw}', 'techniques': [resolved]})
    for keyword, mapped in KEYWORDS:
        if keyword in name:
            resolved = sorted({resolve(t) for t in mapped} - {None})
            if resolved:
                techniques.update(resolved)
                sources.append({'keyword': keyword, 'techniques': resolved})
    return sorted(techniques), sources


def split_of(sha256: str) -> str:
    return 'development' if int(sha256[-1], 16) % 2 == 0 else 'report'


def build(lock: dict, resolve) -> dict:
    by_hash: dict[str, dict] = {}
    for entry in lock['files']:
        if not entry['path'].endswith('.evtx'):
            continue
        sample = by_hash.setdefault(entry['sha256'], {'sha256': entry['sha256'], 'paths': [], 'size': entry['size']})
        sample['paths'].append(entry['path'])
    samples = []
    for digest in sorted(by_hash):
        sample = by_hash[digest]
        sample['paths'].sort()
        techniques, sources = set(), []
        for path in sample['paths']:
            found, why = label(path, resolve)
            techniques.update(found)
            sources.extend(s for s in why if s not in sources)
        sample.update(split=split_of(digest), techniques=sorted(techniques), label_sources=sources,
                      folders=sorted({p.rsplit('/', 1)[0] if '/' in p else '' for p in sample['paths']}),
                      status='labelled' if techniques else 'excluded_undetermined')
        samples.append(sample)
    labelled = [s for s in samples if s['status'] == 'labelled']
    per_technique: dict[str, dict] = {}
    for sample in labelled:
        for technique in sample['techniques']:
            row = per_technique.setdefault(technique, {'development': 0, 'report': 0})
            row[sample['split']] += 1
    return {
        'description': 'Per-file expected ATT&CK techniques for EVTX-ATTACK-SAMPLES, derived only from sample '
                       'paths through the committed keyword table of evaluation/host_technique_manifest.py. '
                       'No sample was opened. Exposed development evidence; labels are coarse.',
        'source': lock['source'], 'commit': lock['commit'], 'attack_version': '20.0',
        'split_rule': 'last hex digit of the content SHA-256: even -> development, odd -> report',
        'counts': {'paths': sum(len(s['paths']) for s in samples), 'samples': len(samples),
                   'duplicate_paths': sum(len(s['paths']) - 1 for s in samples), 'labelled': len(labelled),
                   'excluded_undetermined': len(samples) - len(labelled),
                   'development': sum(s['split'] == 'development' for s in samples),
                   'report': sum(s['split'] == 'report' for s in samples),
                   'labelled_development': sum(s['split'] == 'development' for s in labelled),
                   'labelled_report': sum(s['split'] == 'report' for s in labelled)},
        'per_technique': dict(sorted(per_technique.items())),
        'samples': samples,
    }


def main() -> int:
    sys.path.insert(0, str(ROOT / 'backend'))
    from app.engines.host.sigma_harness import load_remap
    lock = json.loads(LOCK.read_text(encoding='utf-8'))
    manifest = build(lock, load_remap().resolve)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes((json.dumps(manifest, indent=1, ensure_ascii=False) + '\n').encode('utf-8'))
    print(json.dumps(manifest['counts']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
