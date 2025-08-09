#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
pulseproof: оффчейн «доказательство жизни» кошелька через подписанное сообщение.

Возможности:
  1) create  — создать heartbeat JSON и подпись (без ончейн-операций).
  2) verify  — проверить файл/строку heartbeat на валидность и срок годности.
  3) status  — краткий вывод «жив/просрочен» для CI/крон-задач.

Особенности:
- Использует стандарт personal_sign (EIP-191) через eth_account.
- Поддерживает любые EVM-адреса (проверка на соответствие подписи адресу).
- Гибкие поля policy: max_age, required_chain_id, required_tag и т.п.
- Никаких приватных ключей в файлах: ключ берётся из переменной окружения
  PULSEPROOF_PRIVKEY или из защищённого ввода.

Примеры:
  $ export PULSEPROOF_PRIVKEY=0xabc...   # ИЛИ ввести при запросе
  $ python pulseproof.py create --address 0x1234... --tag "my-public-wallet" --max-age 36h > heartbeat.json

  # Проверка файла
  $ python pulseproof.py verify heartbeat.json

  # Короткий статус (возвращает код 0/1 и печатает строку)
  $ python pulseproof.py status heartbeat.json --quiet
"""

import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import click
from eth_account import Account
from eth_account.messages import encode_defunct
from hexbytes import HexBytes

# ----------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ -----------

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_duration_to_seconds(s: str) -> int:
    """
    Простой парсер длительностей: 90m, 36h, 2d, 1w.
    Без внешних зависимостей.
    """
    s = s.strip().lower()
    units = {'m': 60, 'h': 3600, 'd': 86400, 'w': 604800}
    if s.isdigit():
        return int(s)
    for u, mult in units.items():
        if s.endswith(u):
            return int(float(s[:-1]) * mult)
    raise ValueError(f"Неверный формат длительности: {s}")

def load_privkey() -> str:
    pk = os.getenv("PULSEPROOF_PRIVKEY")
    if pk:
        return pk.strip()
    # Запросить безопасно у пользователя
    pk = click.prompt("Введите приватный ключ (hex, начинается с 0x)", hide_input=True)
    return pk.strip()

def normalize_addr(addr: str) -> str:
    if addr.startswith("0x"):
        return addr
    return "0x" + addr

def sign_text(privkey: str, text: str) -> Tuple[str, str]:
    acct = Account.from_key(privkey)
    msg = encode_defunct(text=text)
    signed = acct.sign_message(msg)
    sig = HexBytes(signed.signature).hex()
    return acct.address, sig

def recover_address(text: str, signature: str) -> str:
    msg = encode_defunct(text=text)
    addr = Account.recover_message(msg, signature=HexBytes(signature))
    return addr

def iso_to_dt(s: str) -> datetime:
    return datetime.fromisoformat(s)

# ----------- СУТЬ: СООБЩЕНИЕ И СХЕМА -----------

def compose_heartbeat(address: str,
                      chain_id: Optional[int],
                      tag: str,
                      max_age_seconds: int,
                      extra_note: Optional[str] = None) -> dict:
    """
    Формирует тело heartbeat, которое и подписывается.
    """
    issued_at = now_utc_iso()
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=max_age_seconds)).isoformat()
    hb = {
        "type": "pulseproof.v1",
        "address": normalize_addr(address),
        "chain_id": chain_id,
        "tag": tag,                      # произвольная метка/идентификатор кошелька/профиля
        "issued_at": issued_at,          # ISO 8601 UTC
        "expires_at": expires_at,        # ISO 8601 UTC
        "nonce": str(uuid.uuid4()),      # предотвращает переиспользование
        "algo": "eip191-personal_sign",  # прозрачность алгоритма
        "extra_note": extra_note or "",  # публичная заметка (например, URL профиля)
        "policy": {
            "max_age_sec": max_age_seconds
        },
        # Поле raw_message добавим при сборке: это каноническая строка, которую подписываем.
    }
    # Канонический текст для подписи (минимализм + порядок полей):
    lines = [
        "pulseproof.v1",
        f"address={hb['address']}",
        f"chain_id={hb['chain_id']}",
        f"tag={hb['tag']}",
        f"issued_at={hb['issued_at']}",
        f"expires_at={hb['expires_at']}",
        f"nonce={hb['nonce']}",
        f"algo={hb['algo']}",
        f"extra_note={hb['extra_note']}",
        f"policy.max_age_sec={hb['policy']['max_age_sec']}",
    ]
    hb["raw_message"] = "\n".join(lines)
    return hb

def validate_heartbeat_schema(hb: dict) -> None:
    required = ["type", "address", "issued_at", "expires_at", "nonce", "algo", "raw_message"]
    for r in required:
        if r not in hb:
            raise ValueError(f"Отсутствует обязательное поле: {r}")
    if hb["type"] != "pulseproof.v1":
        raise ValueError("Неподдерживаемый тип heartbeat")
    # Доп. проверки формата времени
    _ = iso_to_dt(hb["issued_at"])
    _ = iso_to_dt(hb["expires_at"])

def is_expired(hb: dict, at: Optional[datetime] = None) -> bool:
    at = at or datetime.now(timezone.utc)
    return at > iso_to_dt(hb["expires_at"])

def verify_signature(hb: dict) -> Tuple[bool, str]:
    try:
        recovered = recover_address(hb["raw_message"], hb["signature"])
        return (recovered.lower() == hb["address"].lower(), recovered)
    except Exception as e:
        return (False, f"Ошибка восстановления: {e}")

# ----------- CLI -----------

@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
def cli():
    """pulseproof — криптографический «пульс» вашего кошелька."""
    pass

@cli.command()
@click.option("--address", required=True, help="EVM-адрес (0x...) для которого создаём heartbeat.")
@click.option("--tag", default="default", show_default=True, help="Метка/идентификатор (напр. имя профиля).")
@click.option("--max-age", default="36h", show_default=True, help="Срок действия: 90m, 36h, 2d, 1w.")
@click.option("--chain-id", type=int, default=None, help="Ожидаемый chain_id (опционально).")
@click.option("--note", default=None, help="Публичная заметка (URL профиля, e-mail, etc.).")
@click.option("--out", type=click.Path(writable=True), default="-", help="Файл вывода JSON или '-' для stdout.")
def create(address, tag, max_age, chain_id, note, out):
    """Создать новый heartbeat и подписать его локальным ключом."""
    try:
        max_age_sec = parse_duration_to_seconds(max_age)
    except Exception as e:
        click.echo(f"Ошибка max-age: {e}", err=True)
        sys.exit(2)

    hb = compose_heartbeat(address=address, chain_id=chain_id, tag=tag,
                           max_age_seconds=max_age_sec, extra_note=note)

    privkey = load_privkey()
    signer_addr, signature = sign_text(privkey, hb["raw_message"])

    if signer_addr.lower() != hb["address"].lower():
        click.echo(
            f"ВНИМАНИЕ: адрес из приватного ключа ({signer_addr}) не совпадает с --address ({hb['address']}).",
            err=True
        )

    hb["signature"] = signature

    data = json.dumps(hb, ensure_ascii=False, indent=2)
    if out == "-" or out is None:
        click.echo(data)
    else:
        with open(out, "w", encoding="utf-8") as f:
            f.write(data)
        click.echo(f"Heartbeat сохранён: {out}")

@cli.command()
@click.argument("source", type=str)
@click.option("--require-fresh", default=None, help="Требовать максимальный возраст (как в create), формат 90m/36h/2d.")
@click.option("--require-chain-id", type=int, default=None, help="Проверить соответствие chain_id (если задан).")
def verify(source, require_fresh, require_chain_id):
    """Проверить heartbeat из файла или JSON-строки."""
    # Загрузка
    if os.path.isfile(source):
        with open(source, "r", encoding="utf-8") as f:
            hb = json.load(f)
    else:
        try:
            hb = json.loads(source)
        except json.JSONDecodeError:
            click.echo("Источник не является ни файлом, ни корректным JSON.", err=True)
            sys.exit(2)

    try:
        validate_heartbeat_schema(hb)
    except Exception as e:
        click.echo(f"Схема некорректна: {e}", err=True)
        sys.exit(2)

    ok_sig, recovered = verify_signature(hb)
    if not ok_sig:
        click.echo(f"Подпись НЕвалидна. Детали: {recovered}", err=True)
        sys.exit(1)

    expired = is_expired(hb)
    freshness_ok = True
    if require_fresh:
        try:
            max_sec = parse_duration_to_seconds(require_fresh)
            age = datetime.now(timezone.utc) - iso_to_dt(hb["issued_at"])
            freshness_ok = age.total_seconds() <= max_sec
        except Exception as e:
            click.echo(f"Ошибка проверки свежести: {e}", err=True)
            sys.exit(2)

    chain_ok = True
    if require_chain_id is not None:
        chain_ok = (hb.get("chain_id") == require_chain_id)

    report = {
        "signature_valid": True,
        "recovered_address": recovered,
        "expired": expired,
        "freshness_ok": freshness_ok,
        "chain_ok": chain_ok
    }
    click.echo(json.dumps(report, ensure_ascii=False, indent=2))
    sys.exit(0 if all(report.values()) and not expired else 1)

@cli.command()
@click.argument("source", type=str)
@click.option("--quiet", is_flag=True, help="Только код возврата и минимальный вывод.")
def status(source, quiet):
    """
    Короткий статус для CI/крон: exit 0 если подпись валидна и не просрочена.
    """
    if os.path.isfile(source):
        with open(source, "r", encoding="utf-8") as f:
            hb = json.load(f)
    else:
        try:
            hb = json.loads(source)
        except json.JSONDecodeError:
            if not quiet:
                click.echo("Некорректный JSON/файл.", err=True)
            sys.exit(2)

    try:
        validate_heartbeat_schema(hb)
        ok_sig, _ = verify_signature(hb)
        expired = is_expired(hb)
        ok = ok_sig and not expired
        if not quiet:
            click.echo("alive" if ok else ("expired" if expired else "invalid"))
        sys.exit(0 if ok else 1)
    except Exception as e:
        if not quiet:
            click.echo(f"Ошибка: {e}", err=True)
        sys.exit(2)

if __name__ == "__main__":
    cli()
