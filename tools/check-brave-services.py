#!/usr/bin/env python3
"""Verify the research-build service patch; optionally evaluate pinned files with GN."""

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'browser/integration/brave/patches/0014-disable-bundled-consumer-services.patch'
FLAGS = {
    'components/ai_chat/core/common/buildflags/buildflags.gni': ['enable_ai_chat'],
    'components/brave_news/common/buildflags/buildflags.gni': ['enable_brave_news'],
    'components/brave_rewards/core/buildflags/buildflags.gni': ['enable_brave_rewards'],
    'components/brave_talk/buildflags/buildflags.gni': ['enable_brave_talk'],
    'components/brave_vpn/common/buildflags/buildflags.gni': [
        'enable_brave_vpn_v1', 'enable_brave_vpn_v2'],
    'components/brave_wallet/common/buildflags/buildflags.gni': ['enable_brave_wallet'],
}
DERIVED = ['enable_brave_vpn', 'enable_brave_vpn_panel', 'enable_brave_vpn_wireguard',
           'enable_brave_vpn_v2_apps', 'enable_brave_ai_chat_agent_profile',
           'enable_ai_chat_tab_management_tool']
SERVICE_ARGS = tuple(flag for flags in FLAGS.values() for flag in flags)
# A generated args.gn may re-enable a patched default. The marker makes that
# override explicit and refuses a marker that names no service.
OPT_IN = 'reb_enable_bundled_brave_services'


def check_patch(text):
    blocks = re.split(r'(?=^diff --git )', text, flags=re.MULTILINE)
    changed = {}
    for block in blocks:
        if not block.startswith('diff --git '):
            continue
        path = block.splitlines()[0].split(' b/', 1)[1]
        if path in changed:
            raise ValueError('Duplicate service patch destination')
        assignments = []
        for line in block.splitlines():
            if not line.startswith('+') or line.startswith('+++'):
                continue
            statement = line[1:].strip()
            if not statement or statement.startswith('#'):
                continue
            match = re.fullmatch(r'(enable_\w+) = (true|false)', statement)
            if match is None:
                raise ValueError('Unexpected executable change in service defaults patch')
            assignments.append(match.groups())
        changed[path] = assignments
    expected = {path: [(flag, 'false') for flag in flags] for path, flags in FLAGS.items()}
    if changed != expected:
        raise ValueError('The service patch must disable exactly the seven requested build defaults')


def strip_gn_comments(text):
    out = []
    quote = None
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            out.append(char)
            if char == '\\' and index + 1 < len(text):
                out.append(text[index + 1])
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in ('"', "'"):
            quote = char
            out.append(char)
            index += 1
            continue
        if char == '#':
            while index < len(text) and text[index] != '\n':
                index += 1
            continue
        out.append(char)
        index += 1
    return ''.join(out)


def check_args(text):
    """Reject a quiet service override and an opt-in that enables nothing."""
    values = {}
    watched = set(SERVICE_ARGS) | {OPT_IN}
    for line in strip_gn_comments(text).splitlines():
        match = re.fullmatch(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*', line)
        if match is None or match.group(1) not in watched:
            continue
        name, value = match.groups()
        if value not in ('true', 'false'):
            raise ValueError(f'{name} must be a literal boolean in args.gn')
        values[name] = value == 'true'
    enabled = [name for name in SERVICE_ARGS if values.get(name)]
    if values.get(OPT_IN) and not enabled:
        raise ValueError(f'{OPT_IN} = true must enable at least one bundled service')
    if enabled and not values.get(OPT_IN):
        raise ValueError(
            'args.gn enables bundled Brave services without '
            f'{OPT_IN} = true: ' + ', '.join(enabled))


def evaluate(brave, gn):
    """Evaluate actual patched GNI files, with only platform/branding imports stubbed."""
    with tempfile.TemporaryDirectory(prefix='reb-service-flags-') as directory:
        root = Path(directory)
        for relative in FLAGS:
            source = brave / relative
            target = root / 'brave' / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            subprocess.run([gn, 'format', '--dry-run', str(source)], check=True)
        (root / '.gn').write_text('buildconfig = "//BUILDCONFIG.gn"\n')
        (root / 'BUILDCONFIG.gn').write_text('set_default_toolchain("//:default")\n')
        stub = root / 'brave/components/brave_origin/buildflags/buildflags.gni'
        stub.parent.mkdir(parents=True, exist_ok=True)
        stub.write_text('is_brave_origin_branded = false\n')
        config = root / 'brave/build/config.gni'
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text('import("//brave/components/brave_origin/buildflags/buildflags.gni")\n')
        imports = ''.join(f'import("//brave/{path}")\n' for path in FLAGS)
        assertions = ''.join(f'assert(!{flag}, "{flag} must be disabled")\n'
                             for flags in FLAGS.values() for flag in flags)
        assertions += ''.join(f'assert(!{flag}, "{flag} must follow its disabled parent")\n'
                              for flag in DERIVED)
        (root / 'BUILD.gn').write_text(imports + assertions + '''
        toolchain("default") {
          tool("stamp") {
            command = "touch {{output}}"
          }
        }
        group("all") {}
        ''')
        for branded in (False, True):
            stub.write_text(f'is_brave_origin_branded = {str(branded).lower()}\n')
            for platform in ('mac', 'win', 'linux', 'android', 'ios'):
                # Official and development configurations use the same disabled services.
                for official in (False, True):
                    values = {f'is_{name}': name == platform
                              for name in ('mac', 'win', 'linux', 'android', 'ios')}
                    values['is_official_build'] = official
                    values['target_os'] = platform
                    configuration = 'set_default_toolchain("//:default")\n'
                    for key, value in values.items():
                        literal = str(value).lower() if isinstance(value, bool) else f'"{value}"'
                        configuration += f'{key} = {literal}\n'
                    (root / 'BUILDCONFIG.gn').write_text(configuration)
                    subprocess.run([gn, 'gen', 'out', '--root=' + str(root)],
                                   check=True, stdout=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--brave', type=Path, help='Already patched pinned brave-core checkout')
    parser.add_argument('--gn', default='gn')
    parser.add_argument('--args', type=Path, help='Component args.gn to check for an explicit service opt-in')
    args = parser.parse_args()
    text = PATCH.read_text()
    check_patch(text)
    # Negative controls ensure removing a service or re-enabling one is rejected.
    for bad in (text.replace('+  enable_ai_chat = false', '+  enable_ai_chat = true'),
                text.replace('+  enable_brave_vpn_v2 = false', '+  omitted = false'),
                text.replace('+  enable_ai_chat = false', '+  enable_ai_chat = false\n+  assert(false)')):
        try:
            check_patch(bad)
        except ValueError:
            continue
        raise AssertionError('A missing or enabled service escaped the patch contract')
    samples = {
        'is_component_build = true\n': None,
        '# enable_ai_chat = true\n': None,
        'enable_ai_chat = false  # leave Leo out\n': None,
        'foo = "enable_ai_chat = true"\n': None,
        'enable_ai_chat = true\nenable_ai_chat = false\n': None,
        'reb_enable_bundled_brave_services = true\nenable_brave_wallet = true\n': None,
        'enable_ai_chat = true\n': 'without reb_enable_bundled_brave_services',
        'reb_enable_bundled_brave_services = true\n': 'at least one bundled service',
        'enable_brave_vpn_v2 = !false\n': 'literal boolean',
        'enable_brave_talk = true\nreb_enable_bundled_brave_services = false\n':
        'without reb_enable_bundled_brave_services',
    }
    for sample, expected in samples.items():
        try:
            check_args(sample)
        except ValueError as error:
            if expected is None or expected not in str(error):
                raise AssertionError(f'args.gn sample rejected unexpectedly: {sample!r} ({error})') from error
        else:
            if expected is not None:
                raise AssertionError(f'args.gn sample was accepted: {sample!r}')
    if args.args:
        if args.args.is_symlink() or not args.args.is_file():
            raise ValueError('Component args.gn must be a regular file')
        check_args(args.args.read_text())
        print('Component args.gn keeps bundled Brave services opt-in')
    if args.brave:
        evaluate(args.brave, args.gn)
        print('Patched GN service defaults and derived flags passed all 20 configurations')
    else:
        print('Service patch contract passed; upstream GN evaluation was not requested')


if __name__ == '__main__':
    try:
        main()
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
