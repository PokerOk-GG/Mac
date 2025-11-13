#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pokerok.py — набор утилит для проверки и взаимодействия с pokerok.dmg

Возможности (все подкоманды смотрят на один файл DMG):
  - hash        — посчитать SHA-256 и размер файла
  - info        — прочесть метаданные образа через hdiutil (plist)
  - mount       — смонтировать образ (ro, nobrowse) и вернуть точку монтирования + устройство
  - list        — смонтировать, показать содержимое верхнего уровня, затем отмонтировать
  - copy        — смонтировать и скопировать .app в указанную директорию (по умолчанию /Applications)
  - verify      — проверить .app (Gatekeeper: spctl) и подпись (codesign) из смонтированного образа
  - detach      — отмонтировать по устройству (-dev) или пути монтирования (-m)

Примеры:
  python3 pokerok_dmg_tools.py hash pokerok.dmg
  python3 pokerok_dmg_tools.py info pokerok.dmg
  python3 pokerok_dmg_tools.py list pokerok.dmg
  python3 pokerok_dmg_tools.py copy pokerok.dmg --dest /Applications --dry-run
  python3 pokerok_dmg_tools.py verify pokerok.dmg
  python3 pokerok_dmg_tools.py mount pokerok.dmg --mountpoint /tmp/pokerok_mnt
  python3 pokerok_dmg_tools.py detach -m /tmp/pokerok_mnt
"""

import argparse
import hashlib
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Tuple

def run(cmd, check=True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, text=True, capture_output=True)

def sha256sum(path: Path) -> Tuple[str, int]:
    h = hashlib.sha256()
    total = 0
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
            total += len(chunk)
    return h.hexdigest(), total

def hdiutil_imageinfo_plist(dmg: Path) -> dict:
    res = run(['hdiutil', 'imageinfo', '-plist', str(dmg)])
    return plistlib.loads(res.stdout.encode())

def hdiutil_attach(dmg: Path, mountpoint: Optional[Path] = None) -> Tuple[Path, str]:
    """
    Возвращает (mountpoint, device). Монтирует read-only, nobrowse, noverify.
    """
    args = ['hdiutil', 'attach', str(dmg), '-readonly', '-nobrowse', '-noverify', '-plist']
    if mountpoint:
        mountpoint.mkdir(parents=True, exist_ok=True)
        args += ['-mountpoint', str(mountpoint)]
    res = run(args)
    pl = plistlib.loads(res.stdout.encode())
    # Ищем запись с mount-point и device
    device = None
    mnt = None
    for ent in pl.get('system-entities', []):
        if 'mount-point' in ent:
            mnt = Path(ent['mount-point'])
        if 'dev-entry' in ent and ent.get('content-hint', '').startswith('Apple_HFS'):
            device = ent['dev-entry']
    if not mnt:
        # fallback: берем первый встреченный mount-point
        for ent in pl.get('system-entities', []):
            if 'mount-point' in ent:
                mnt = Path(ent['mount-point']); break
    if not device:
        # fallback: первый dev-entry
        for ent in pl.get('system-entities', []):
            if 'dev-entry' in ent:
                device = ent['dev-entry']; break
    if not (mnt and device):
        raise RuntimeError("Не удалось определить точку монтирования или устройство.")
    return mnt, device

def hdiutil_detach(target: str) -> None:
    # target может быть /dev/diskX или путь монтирования
    try:
        run(['hdiutil', 'detach', target])
    except subprocess.CalledProcessError as e:
        # Иногда помогает -force
        run(['hdiutil', 'detach', '-force', target])

def list_top(mountpoint: Path) -> list:
    items = []
    for p in sorted(mountpoint.iterdir()):
        items.append(f"{'[D]' if p.is_dir() else '[F]'} {p.name}")
    return items

def find_app_bundle(mountpoint: Path) -> Optional[Path]:
    for p in mountpoint.rglob('*.app'):
        # Обычно на верхнем уровне
        return p
    return None

def copy_app(app_src: Path, dest_dir: Path, dry_run: bool = False) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / app_src.name
    if dry_run:
        print(f"[DRY-RUN] Скопировал бы: {app_src} -> {dest}")
        return dest
    if dest.exists():
        # Удалим старую версию, чтобы не смешивать содержимое
        if dest.is_dir():
            shutil.rmtree(dest)
        else:
            dest.unlink()
    shutil.copytree(app_src, dest, symlinks=True)
    return dest

def spctl_assess(app_path: Path) -> Tuple[bool, str]:
    # gatekeeper assessment
    try:
        res = run(['spctl', '--assess', '--type', 'execute', '--verbose', str(app_path)], check=True)
        return True, res.stderr.strip() or res.stdout.strip()
    except subprocess.CalledProcessError as e:
        return False, (e.stderr or e.stdout).strip()

def codesign_verify(app_path: Path) -> Tuple[bool, str]:
    # Проверка целостности подписи
    try:
        res = run(['codesign', '--verify', '--deep', '--strict', '--verbose=2', str(app_path)], check=True)
        return True, res.stderr.strip() or res.stdout.strip()
    except subprocess.CalledProcessError as e:
        return False, (e.stderr or e.stdout).strip()

def cmd_hash(args):
    h, size = sha256sum(Path(args.dmg))
    print(f"Файл: {args.dmg}")
    print(f"SHA-256: {h}")
    print(f"Размер: {size} байт ({size/1024/1024:.2f} МБ)")

def cmd_info(args):
    pl = hdiutil_imageinfo_plist(Path(args.dmg))
    fields = {
        'Format': pl.get('Format'),
        'Block Count': pl.get('block-count'),
        'Sector Size': pl.get('sector-size'),
        'Checksum Type': pl.get('checksum-type'),
        'Checksum': pl.get('checksum'),
        'Partitions': pl.get('Partitions'),
        'Software License Agreement': pl.get('software-license-agreement'),
    }
    print(f"Информация об образе: {args.dmg}")
    for k, v in fields.items():
        if v is not None:
            print(f"- {k}: {v}")

def cmd_mount(args):
    dmg = Path(args.dmg)
    mnt = Path(args.mountpoint) if args.mountpoint else Path(tempfile.mkdtemp(prefix='pokerok_mnt_'))
    mp, dev = hdiutil_attach(dmg, mnt)
    print(f"Смонтировано: {mp}\nУстройство: {dev}")
    print("Подсказка: для отмонтирования используйте: detach -m <mountpoint> или detach -dev <device>")

def cmd_list(args):
    dmg = Path(args.dmg)
    with tempfile.TemporaryDirectory(prefix='pokerok_mnt_') as tmp:
        mp, dev = hdiutil_attach(dmg, Path(tmp))
        try:
            print(f"Содержимое {mp}:")
            for line in list_top(mp):
                print("  ", line)
        finally:
            hdiutil_detach(dev)

def cmd_copy(args):
    dmg = Path(args.dmg)
    dest = Path(args.dest).expanduser()
    with tempfile.TemporaryDirectory(prefix='pokerok_mnt_') as tmp:
        mp, dev = hdiutil_attach(dmg, Path(tmp))
        try:
            app = find_app_bundle(mp)
            if not app:
                raise RuntimeError("В образе не найден .app пакет.")
            out = copy_app(app, dest, dry_run=args.dry_run)
            print(f"{'[DRY-RUN] ' if args.dry_run else ''}Готово: {out}")
        finally:
            hdiutil_detach(dev)

def cmd_verify(args):
    dmg = Path(args.dmg)
    with tempfile.TemporaryDirectory(prefix='pokerok_mnt_') as tmp:
        mp, dev = hdiutil_attach(dmg, Path(tmp))
        try:
            app = find_app_bundle(mp)
            if not app:
                raise RuntimeError("В образе не найден .app пакет.")
            print(f"Проверяем: {app}")
            ok_gate, msg_gate = spctl_assess(app)
            print(f"Gatekeeper: {'OK' if ok_gate else 'FAIL'} — {msg_gate}")
            ok_sign, msg_sign = codesign_verify(app)
            print(f"codesign:   {'OK' if ok_sign else 'FAIL'} — {msg_sign}")
        finally:
            hdiutil_detach(dev)

def cmd_detach(args):
    target = None
    if args.device:
        target = args.device
    elif args.mountpoint:
        target = args.mountpoint
    else:
        print("Укажите -dev ИЛИ -m для отмонтирования.", file=sys.stderr)
        sys.exit(2)
    hdiutil_detach(target)
    print(f"Отмонтировано: {target}")

def build_parser():
    p = argparse.ArgumentParser(description="Инструменты для проверки/работы с pokerok.dmg на macOS")
    sub = p.add_subparsers(dest='cmd', required=True)

    ph = sub.add_parser('hash', help='Посчитать SHA-256 и размер файла')
    ph.add_argument('dmg')
    ph.set_defaults(func=cmd_hash)

    pi = sub.add_parser('info', help='Показать метаданные DMG (hdiutil -plist)')
    pi.add_argument('dmg')
    pi.set_defaults(func=cmd_info)

    pm = sub.add_parser('mount', help='Смонтировать DMG и напечатать mountpoint/device')
    pm.add_argument('dmg')
    pm.add_argument('--mountpoint', '-m', help='Желаемая точка монтирования')
    pm.set_defaults(func=cmd_mount)

    pl = sub.add_parser('list', help='Смонтировать, показать содержимое верхнего уровня, отмонтировать')
    pl.add_argument('dmg')
    pl.set_defaults(func=cmd_list)

    pc = sub.add_parser('copy', help='Скопировать .app из DMG (по умолчанию в /Applications)')
    pc.add_argument('dmg')
    pc.add_argument('--dest', default='/Applications')
    pc.add_argument('--dry-run', action='store_true', help='Только показать, что будет скопировано')
    pc.set_defaults(func=cmd_copy)

    pv = sub.add_parser('verify', help='Проверить Gatekeeper и codesign .app внутри DMG')
    pv.add_argument('dmg')
    pv.set_defaults(func=cmd_verify)

    pd = sub.add_parser('detach', help='Отмонтировать по устройству или mountpoint')
    g = pd.add_mutually_exclusive_group(required=True)
    g.add_argument('-dev', '--device', help='Напр. /dev/disk4')
    g.add_argument('-m', '--mountpoint', help='Путь точки монтирования')
    pd.set_defaults(func=cmd_detach)

    return p

def main():
    if sys.platform != 'darwin':
        print("Внимание: этот скрипт рассчитан на macOS (darwin).", file=sys.stderr)
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except subprocess.CalledProcessError as e:
        print(f"Команда завершилась ошибкой [{e.returncode}]: {' '.join(e.cmd)}", file=sys.stderr)
        if e.stdout:
            print("STDOUT:\n" + e.stdout, file=sys.stderr)
        if e.stderr:
            print("STDERR:\n" + e.stderr, file=sys.stderr)
        sys.exit(e.returncode)
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()