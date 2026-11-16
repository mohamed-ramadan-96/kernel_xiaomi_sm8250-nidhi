#!/usr/bin/env python3
"""Apply Darkdreamer alioth build options to the selected Nidhi kernel source.

The script is intentionally fail-closed: it only edits known SM8250/QPNP-SMB5
layouts and aborts when an expected source anchor is missing or ambiguous.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    print(f"::error::{message}", file=sys.stderr)
    raise SystemExit(1)


def read(path: Path) -> str:
    if not path.is_file():
        fail(f"Required kernel source file is missing: {path}")
    return path.read_text(encoding="utf-8")


def write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        fail(f"{label}: expected one source anchor, found {count}; refusing an unsafe edit.")
    return text.replace(old, new, 1)


def ensure_before(text: str, anchor: str, block: str, label: str) -> str:
    if block.strip() in text:
        return text
    count = text.count(anchor)
    if count != 1:
        fail(f"{label}: expected one insertion anchor, found {count}.")
    return text.replace(anchor, block + anchor, 1)


def set_config(path: Path, symbol: str, enabled: bool) -> None:
    content = read(path)
    content = re.sub(
        rf"(?m)^[ \t]*(?:#\s*)?CONFIG_{re.escape(symbol)}(?:=.*)?\r?\n",
        "",
        content,
    )
    state = f"CONFIG_{symbol}=y" if enabled else f"# CONFIG_{symbol} is not set"
    write(path, content.rstrip() + "\n" + state + "\n")


def add_rw_swappiness(source: Path, enabled: bool) -> None:
    kconfig_path = source / "mm/Kconfig"
    kconfig = read(kconfig_path)
    if not re.search(r"(?m)^config RW_SWAPPINESS\s*$", kconfig):
        block = (
            'config RW_SWAPPINESS\n'
            '\tbool "Allow users to modify vm.swappiness at runtime"\n'
            '\tdepends on SWAP\n'
            '\tdefault n\n'
            '\thelp\n'
            '\t  Make vm.swappiness writable (0644) for privileged users.\n'
            '\t  When disabled, keep the sysctl read-only (0444).\n\n'
        )
        kconfig = ensure_before(kconfig, "config CMA\n", block, "RW_SWAPPINESS Kconfig")
        write(kconfig_path, kconfig)

    sysctl_path = source / "kernel/sysctl.c"
    sysctl = read(sysctl_path)
    match = re.search(
        r'(?P<head>\t\{\n\t\t\.procname\s*=\s*"swappiness",[\s\S]*?'
        r'\.maxlen\s*=\s*sizeof\(vm_swappiness\),\n)'
        r'(?P<mode>\s*\.mode\s*=\s*(?:0644|0444),)',
        sysctl,
    )
    if match:
        mode = (
            '#ifdef CONFIG_RW_SWAPPINESS\n'
            '\t\t.mode\t\t= 0644,\n'
            '#else\n'
            '\t\t.mode\t\t= 0444,\n'
            '#endif'
        )
        sysctl = sysctl[:match.start("mode")] + mode + sysctl[match.end("mode"):]
        write(sysctl_path, sysctl)
    elif not re.search(r'(?s)\.procname\s*=\s*"swappiness",.*?#ifdef CONFIG_RW_SWAPPINESS', sysctl):
        fail("RW_SWAPPINESS: could not safely locate the vm.swappiness sysctl mode.")

    common_config = source / "arch/arm64/configs/vendor/xiaomi/magictime-common.config"
    set_config(common_config, "RW_SWAPPINESS", enabled)
    print(f"RW_SWAPPINESS: {'enabled' if enabled else 'disabled'}")


def function_body_replace(content: str, function: str, replacement_body: str) -> str:
    pattern = re.compile(
        rf"(?ms)^(?P<head>(?:static\s+)?[\w\s\*]+\b{re.escape(function)}\s*\([^;]*?\)\s*\{{)"
        rf"(?P<body>.*?)^(?P<tail>\}})",
    )
    matches = list(pattern.finditer(content))
    if len(matches) != 1:
        fail(f"Bypass Charging: expected one definition of {function}(), found {len(matches)}.")
    match = matches[0]
    return content[:match.start("body")] + replacement_body + "\n" + content[match.end("body"):]


def add_bypass_charging(source: Path) -> None:
    kconfig_path = source / "drivers/power/supply/Kconfig"
    kconfig = read(kconfig_path)
    if not re.search(r"(?m)^config BYPASS_CHARGING\s*$", kconfig):
        block = (
            'config BYPASS_CHARGING\n'
            '\tbool "Allow bypass charging"\n'
            '\tdefault n\n'
            '\thelp\n'
            '\t  Enable the QPNP-SMB5 bypass charging mode.\n\n'
        )
        kconfig = ensure_before(
            kconfig, 'source "drivers/power/supply/qcom/Kconfig"\n',
            block, "BYPASS_CHARGING Kconfig"
        )
        write(kconfig_path, kconfig)

    header_path = source / "drivers/power/supply/qcom/smb5-lib.h"
    header = read(header_path)
    if "BYPASS_VOTER" not in header:
        header = ensure_before(
            header, "/* use for QC3P5 */",
            '#ifdef CONFIG_BYPASS_CHARGING\n'
            '#define BYPASS_VOTER\t\t\t"BYPASS_VOTER"\n'
            '#endif\n',
            "BYPASS_VOTER definition"
        )
        write(header_path, header)

    lib_path = source / "drivers/power/supply/qcom/smb5-lib.c"
    lib = read(lib_path)
    if "CONFIG_BYPASS_CHARGING" not in lib:
        lib = replace_once(
            lib, "static bool first_boot_flag;\n",
            "static bool first_boot_flag;\n"
            "#ifdef CONFIG_BYPASS_CHARGING\n"
            "static int bypass_charging;\n"
            "#endif\n",
            "bypass state declaration"
        )

        getter_body = '''
#ifdef CONFIG_BYPASS_CHARGING
\tif (get_client_vote(chg->chg_disable_votable, BYPASS_VOTER) == 1)
\t\tval->intval = 1;
\telse if (bypass_charging)
\t\tval->intval = 2;
\telse
\t\tval->intval = 0;
#else
\tval->intval
\t\t= (get_client_vote(chg->usb_icl_votable, USER_VOTER) == 0)
\t\t || get_client_vote(chg->dc_suspend_votable, USER_VOTER);
#endif
\treturn 0;'''
        lib = function_body_replace(lib, "smblib_get_prop_input_suspend", getter_body)

        setter_body = '''
	int rc;
#ifdef CONFIG_BYPASS_CHARGING
\t/* Keep the input path active while the charger IC bypasses battery charging. */
\trc = vote(chg->usb_icl_votable, USER_VOTER, false, 0);
\tif (rc < 0) {
\t\tsmblib_err(chg, "Couldn't vote to resume USB rc=%d\\n", rc);
\t\treturn rc;
\t}
\trc = vote(chg->dc_suspend_votable, USER_VOTER, false, 0);
\tif (rc < 0) {
\t\tsmblib_err(chg, "Couldn't vote to resume DC rc=%d\\n", rc);
\t\treturn rc;
\t}
\tif (val->intval == 1) {
\t\trc = vote(chg->chg_disable_votable, BYPASS_VOTER, 1, 0);
\t\tbypass_charging = 0;
\t} else if (val->intval == 2) {
\t\trc = vote(chg->chg_disable_votable, BYPASS_VOTER, 0, 0);
\t\tbypass_charging = 1;
\t} else {
\t\trc = vote(chg->chg_disable_votable, BYPASS_VOTER, 0, 0);
\t\tbypass_charging = 0;
\t}
\tif (rc < 0) {
\t\tsmblib_err(chg, "Couldn't vote to %d input_suspend rc=%d\\n",
\t\t\tval->intval, rc);
\t\treturn rc;
\t}
#else
\trc = vote(chg->usb_icl_votable, USER_VOTER, (bool)val->intval, 0);
\tif (rc < 0) {
\t\tsmblib_err(chg, "Couldn't vote to %s USB rc=%d\\n",
\t\t\t(bool)val->intval ? "suspend" : "resume", rc);
\t\treturn rc;
\t}
\trc = vote(chg->dc_suspend_votable, USER_VOTER, (bool)val->intval, 0);
\tif (rc < 0) {
\t\tsmblib_err(chg, "Couldn't vote to %s DC rc=%d\\n",
\t\t\t(bool)val->intval ? "suspend" : "resume", rc);
\t\treturn rc;
\t}
#endif
\tpower_supply_changed(chg->batt_psy);
\treturn rc;'''
        lib = function_body_replace(lib, "smblib_set_prop_input_suspend", setter_body)

        thermal_anchor = (
            '\tstruct smb_charger *chg = container_of(work, struct smb_charger,\n'
            '\t\t\tthermal_setting_work.work);\n'
        )
        lib = replace_once(
            lib, thermal_anchor,
            thermal_anchor +
            '#ifdef CONFIG_BYPASS_CHARGING\n'
            '\tif (bypass_charging)\n'
            '\t\tchg->pps_thermal_level = 0;\n'
            '#endif\n',
            "bypass thermal work"
        )

        temp_anchor = '\tif (chg->pd_active == POWER_SUPPLY_PD_PPS_ACTIVE)\n\t\tschedule_delayed_work(&chg->thermal_setting_work, 3 * HZ);'
        lib = replace_once(
            lib, temp_anchor,
            '#ifdef CONFIG_BYPASS_CHARGING\n'
            '\tif (bypass_charging)\n'
            '\t\tchg->system_temp_level = 0;\n'
            '#endif\n' + temp_anchor,
            "bypass system thermal level"
        )
        write(lib_path, lib)
    else:
        required = [
            "static int bypass_charging",
            "BYPASS_VOTER",
            "chg->pps_thermal_level = 0",
            "chg->system_temp_level = 0",
        ]
        missing = [marker for marker in required if marker not in lib]
        if missing:
            fail("BYPASS_CHARGING is only partially present in smb5-lib.c: " + ", ".join(missing))

    qpnp = read(source / "drivers/power/supply/qcom/qpnp-smb5.c")
    if "POWER_SUPPLY_PROP_INPUT_SUSPEND" not in qpnp or "smblib_set_prop_input_suspend" not in qpnp:
        fail("Bypass Charging requires the existing QPNP-SMB5 input_suspend property/setter interface.")

    common_config = source / "arch/arm64/configs/vendor/xiaomi/magictime-common.config"
    set_config(common_config, "BYPASS_CHARGING", True)
    print("BYPASS_CHARGING: implementation backport verified and enabled")


def select_battery_profile(source: Path, profile: str, device: str) -> None:
    if device != "alioth":
        print(f"Battery profile selection skipped: {device} is not alioth.")
        return

    dts_path = source / "arch/arm64/boot/dts/vendor/qcom/alioth-sm8250.dtsi"
    dts = read(dts_path)
    j3s = re.compile(r"(?m)^[ \t]*qcom,j3s-batt-profile;[ \t]*\r?\n")
    mah5000 = re.compile(
        r'(?m)^[ \t]*#include[ \t]+"fg-gen4-batterydata-apollo-sun-5000mah\.dtsi"[ \t]*\r?\n'
    )
    j3s_count = len(j3s.findall(dts))
    mah5000_count = len(mah5000.findall(dts))

    if profile == "j3s":
        if j3s_count != 1 or mah5000_count != 1:
            fail("Battery profile: j3s requires exactly one j3s selector and one 5000mAh data include.")
    elif profile == "stk":
        if (j3s_count, mah5000_count) == (1, 1):
            dts = j3s.sub("", dts)
            dts = mah5000.sub("", dts)
        elif (j3s_count, mah5000_count) != (0, 0):
            fail("Battery profile: partial/ambiguous j3s selection detected; refusing to guess.")
        if "fg-gen4-batterydata-alioth-FMT-4520mah.dtsi" not in dts or "fg-gen4-batterydata-alioth-GY-4520mah.dtsi" not in dts:
            fail("Battery profile: 4520mAh FMT/GY tables were not found after selecting stk.")
    else:
        fail(f"Unknown battery profile: {profile}")

    write(dts_path, dts)
    print(f"Battery profile: {profile} ({'5000mAh j3s' if profile == 'j3s' else '4520mAh stock'})")


def apply_j3s_profile_driver_override(source: Path) -> None:
    """Make the explicit J3S workflow choice authoritative when DS28E16 Page 0 is unreadable."""
    driver_path = source / "drivers/power/supply/qcom/qpnp-fg-gen4.c"
    driver = read(driver_path)
    dts = read(source / "arch/arm64/boot/dts/vendor/qcom/alioth-sm8250.dtsi")

    if "fg-gen4-batterydata-apollo-sun-5000mah.dtsi" not in dts:
        fail("Battery profile: J3S driver override requires the 5000mAh J3S battery-data include.")

    marker = 'pr_alert("DTBO Flag found: Forcing j3ssun_5000mah profile\\n");'
    if marker in driver:
        required = [
            "fg->profile_already_find = true;",
            "retry_batt_profile = BATT_PROFILE_RETRY_COUNT_MAX;",
            '"j3ssun_5000mah"',
        ]
        missing = [item for item in required if item not in driver]
        if missing:
            fail("Battery profile: existing J3S override is incomplete: " + ", ".join(missing))
        print("Battery profile driver: existing explicit J3S override verified")
        return

    anchor = "\t\tprofile_node = ERR_PTR(-ENXIO);\n"
    block = (
        "\t\t/* The workflow's explicit J3S selection must not depend on DS28E16 Page 0. */\n"
        "\t\tif (chip->dt.j3s_batt_profile && !fg->profile_already_find) {\n"
        "\t\t\tpr_alert(\"DTBO Flag found: Forcing j3ssun_5000mah profile\\n\");\n"
        "\t\t\tfg->profile_already_find = true;\n"
        "\t\t\t/* Stop the verify retry path after an explicit profile selection. */\n"
        "\t\t\tretry_batt_profile = BATT_PROFILE_RETRY_COUNT_MAX;\n"
        "\t\t\tprofile_node = of_batterydata_get_best_profile(batt_node,\n"
        "\t\t\t\tfg->batt_id_ohms / 1000, \"j3ssun_5000mah\");\n"
        "\t\t}\n"
    )

    if driver.count(anchor) != 1:
        fail("Battery profile: could not uniquely locate the DS28E16 profile-selection entry point; refusing an unsafe driver edit.")
    if "BATT_PROFILE_RETRY_COUNT_MAX" not in driver or "fg->profile_already_find" not in driver:
        fail("Battery profile: selected kernel driver lacks the expected DS28E16 retry/profile state.")

    driver = driver.replace(anchor, anchor + block, 1)
    write(driver_path, driver)
    print("Battery profile driver: explicit J3S override applied (independent of DS28E16 Page 0)")

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--device", required=True)
    parser.add_argument("--battery-profile", choices=("j3s", "stk"), default="j3s")
    parser.add_argument("--bypass-charging", choices=("true", "false"), default="false")
    parser.add_argument("--rw-swappiness", choices=("true", "false"), default="false")
    args = parser.parse_args()

    source = args.source_dir.resolve()
    if not (source / "build.sh").is_file():
        fail(f"Selected source is not a Nidhi build.sh-compatible kernel tree: {source}")

    select_battery_profile(source, args.battery_profile, args.device)
    if args.device == "alioth":
        apply_j3s_profile_driver_override(source)
    if args.bypass_charging == "true":
        add_bypass_charging(source)
    else:
        kconfig = read(source / "drivers/power/supply/Kconfig")
        if re.search(r"(?m)^config BYPASS_CHARGING\\s*$", kconfig):
            set_config(source / "arch/arm64/configs/vendor/xiaomi/magictime-common.config",
                       "BYPASS_CHARGING", False)
        print("BYPASS_CHARGING: disabled")

    add_rw_swappiness(source, args.rw_swappiness)

    summary = Path(__import__("os").environ.get("GITHUB_STEP_SUMMARY", ""))
    if str(summary) and summary.is_file():
        with summary.open("a", encoding="utf-8") as stream:
            stream.write("### Darkdreamer feature integration\n")
            stream.write(f"- Battery profile: {args.battery_profile if args.device == 'alioth' else 'not applicable'}\n")
            stream.write(f"- Bypass charging: {args.bypass_charging}\n")
            stream.write(f"- Writable swappiness: {args.rw_swappiness}\n")


if __name__ == "__main__":
    main()
