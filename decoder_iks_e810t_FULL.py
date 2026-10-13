#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Улучшенный декодер логов фискального регистратора ІКС-Е810Т (IKS E810T / EP-08).
Протокол: DLE=0x10, STX=0x02, ETX=0x03, ACK=0x06, SYN=0x16, NAK=0x15.
Строки — CP866.

Улучшения:
- Схлопывание [NUL]: вместо длинных цепочек — [NUL×N]
- Подсчёт ненулевых байт в [Размер: Xб, ненулевых: Y]
- Названия команд рядом с кодом
- Расширенный разбор ModemPar (cmd 53), Discount (35), и текстовых полей
"""

import glob
import os
import re
import sys
from typing import List, Tuple, Optional, Dict

# ========================= Справочник команд =========================

CMD_NAMES: Dict[int, str] = {
    0: "SendStatus",
    1: "OpenShift",
    2: "CloseShift",
    9: "DayReport (X)",
    10: "ArtReport",
    11: "Comment",
    12: "Sale (регистрация продажи)",
    13: "DayClrReport (Z)",
    14: "Payment",
    15: "CancelCheck",
    16: "Avans (служебный внос)",
    17: "PeriodicReport",
    18: "Sale",
    20: "Payment",
    21: "Fiscalization",
    22: "SetHeadLine",
    23: "Discount (скидка/наценка)",
    25: "SetTaxRate",
    26: "PeriodicReportShort",
    27: "DisplayText",
    28: "GetTime",
    29: "SetTime",
    31: "PeriodicReport2",
    33: "GetBox",
    34: "ProgArt",
    35: "Discount",
    42: "GetDayReport",
    43: "GetCheckSums",
    44: "GetTaxRates",
    45: "LoadBMP",
    46: "CplCutter",
    47: "SetBarCode",
    48: "GetPapStat",
    49: "ArtBarCode",
    52: "Personaliz",
    53: "ModemPar",
    54: "SetIndType",
    58: "?",  # встречается в логах
}

MODEM_TAGS: Dict[int, str] = {
    1: "инициировать обмен с эквайером",
    2: "безусловный обмен с эквайером",
    3: "получить пакет КСЕФ",
    4: "состояние модема (структура)",
    5: "состояние модема (текст)",
    8: "проверить пакет КСЕФ",
    9: "получить номер пакета КСЕФ",
    10: "текущая задача модема",
}

MODEM_ERR: Dict[int, str] = {
    0: "OK",
    1: "общая ошибка модема",
    2: "таймаут старта задачи",
    3: "нет записи персонализации в КСЕФ",
    4: "ошибка служебной области КСЕФ",
    5: "ошибка записи КСЕФ",
    6: "ошибка создания пакета КСЕФ",
    7: "ошибка чтения пакета КСЕФ",
    8: "РРО не фискализирован",
    9: "ошибка данных от фискального блока",
    10: "КСЕФ заполнен",
    11: "неверный номер пакета КСЕФ",
    12: "ошибка подписи пакета КСЕФ",
    13: "SAM занят",
    14: "ошибка SAM",
    15: "данные КСЕФ повреждены",
    16: "неизвестный код команды",
    251: "команда не может быть выполнена",
    252: "модем занят",
    253: "внутренняя ошибка модема",
    254: "таймаут считывания ФБ",
    255: "общая ошибка модема",
}

# ========================= Вспомогательные функции =========================

def hex_tokens_to_bytes(tokens: List[str]) -> bytes:
    out = bytearray()
    for t in tokens:
        t = t.strip()
        if t.lower().startswith("0x"):
            try:
                out.append(int(t, 16) & 0xFF)
            except ValueError:
                pass
    return bytes(out)


def cp866_decode(b: bytes) -> str:
    try:
        s = b.decode("cp866", errors="replace")
    except Exception:
        s = b.decode("latin1", errors="replace")
    return "".join(c if (c.isprintable() or c in " \t") else f"[{ord(c):02X}]" for c in s)


def le_uint(data: bytes, signed=False) -> int:
    if not data:
        return 0
    return int.from_bytes(data, "little", signed=signed)


def money_str(kopecks: int) -> str:
    sign = "-" if kopecks < 0 else ""
    kopecks = abs(kopecks)
    return f"{sign}{kopecks // 100}.{kopecks % 100:02d}"


def collapse_nuls_and_ctrl(text: str) -> str:
    """
    Схлопывает последовательности [NUL] / [00] и т.п.
    [NUL][NUL][NUL] → [NUL×3]
    Также убирает хвостовые [NUL×N] в конце.
    """
    # Схлопываем подряд идущие [NUL]
    def repl_nul(m):
        n = m.group(0).count("[NUL]")
        return f"[NUL×{n}]" if n > 1 else "[NUL]"

    text = re.sub(r"(?:\[NUL\]){2,}", repl_nul, text)

    # Схлопываем подряд [00] если остались
    def repl_00(m):
        n = len(m.group(0)) // 4  # [00]
        return f"[00×{n}]" if n > 1 else "[00]"

    text = re.sub(r"(?:\[00\]){2,}", repl_00, text)

    # Убираем хвостовые [NUL×N] / [NUL]
    text = re.sub(r"(?:\s*\[NUL(?:×\d+)?\])+\s*$", "", text)
    text = re.sub(r"(?:\s*\[00(?:×\d+)?\])+\s*$", "", text)
    return text.strip()


def count_nonzero(data: bytes) -> int:
    return sum(1 for b in data if b != 0)


def smart_bytes_to_text(data: bytes, collapse: bool = True) -> str:
    """
    Умное представление байтов + схлопывание NUL.
    Возвращает текст и (опционально) статистику через вызывающего.
    """
    if not data:
        return ""

    result = []
    i = 0
    while i < len(data):
        # Длинные ASCII-фрагменты (URL и т.п.)
        if 32 <= data[i] <= 126:
            j = i
            while j < len(data) and 32 <= data[j] <= 126:
                j += 1
            if j - i >= 6:
                result.append(data[i:j].decode("ascii"))
                i = j
                continue

        b = data[i]
        if b == 0x00:
            result.append("[NUL]")
        elif b == 0x20:
            result.append(" ")
        elif 32 <= b <= 126:
            result.append(chr(b))
        elif b >= 0x80:
            try:
                c = bytes([b]).decode("cp866")
                if c.isprintable():
                    result.append(c)
                else:
                    result.append(f"[{b:02X}]")
            except Exception:
                result.append(f"[{b:02X}]")
        else:
            ctrl = {
                0x02: "STX", 0x03: "ETX", 0x05: "ENQ", 0x06: "ACK",
                0x10: "DLE", 0x11: "DC1", 0x12: "DC2", 0x15: "NAK",
                0x16: "SYN", 0x17: "ETB", 0x1B: "ESC", 0x1C: "FS",
                0x1D: "GS", 0x1E: "RS", 0x1F: "US",
            }
            result.append(f"[{ctrl.get(b, f'{b:02X}')}]")
        i += 1

    text = "".join(result)
    text = re.sub(r"[ \t]+", " ", text).strip()
    if collapse:
        text = collapse_nuls_and_ctrl(text)
    return text


# ========================= Разбор пакета =========================

def find_packet(data: bytes) -> Optional[Tuple[int, int, bytes]]:
    i = 0
    while i < len(data) - 3:
        if data[i] == 0x10 and data[i + 1] == 0x02:
            payload = bytearray()
            j = i + 2
            while j < len(data) - 1:
                if data[j] == 0x10 and data[j + 1] == 0x03:
                    return i, j + 2, bytes(payload)
                if data[j] == 0x10 and j + 1 < len(data) and data[j + 1] == 0x10:
                    payload.append(0x10)
                    j += 2
                else:
                    payload.append(data[j])
                    j += 1
            break
        i += 1
    return None


def cmd_label(cmd: int) -> str:
    name = CMD_NAMES.get(cmd)
    if name:
        return f"Cmd={cmd:02X}({cmd}/{name})"
    return f"Cmd={cmd:02X}({cmd})"


def decode_modem_par(data: bytes, is_response: bool) -> str:
    """Команда 53 — ModemPar."""
    if not data:
        return "[нет данных]"

    if is_response:
        # Ответ: код результата (1) + длина n (2) + данные n
        if len(data) >= 3:
            code = data[0]
            n = le_uint(data[1:3])
            payload = data[3:3 + n] if n else b""
            err = MODEM_ERR.get(code, f"код={code}")
            txt = smart_bytes_to_text(payload) if payload else ""
            parts = [f"Result={code}({err})"]
            if n:
                parts.append(f"Len={n}")
            if txt:
                parts.append(f"Data: {txt}")
            # Если структура не совпала — fallback
            if not txt and data:
                parts.append(f"Raw: {smart_bytes_to_text(data)}")
            return " | ".join(parts)
        return smart_bytes_to_text(data)

    # Запрос: reserved(2) + len(2) + tag(1) + ...
    if len(data) >= 5:
        reserved = le_uint(data[0:2])
        n = le_uint(data[2:4])
        tag = data[4]
        tag_name = MODEM_TAGS.get(tag, f"tag={tag}")
        rest = data[5:5 + max(0, n - 1)] if n else data[5:]
        parts = [f"Tag={tag}({tag_name})"]
        if n:
            parts.append(f"ParamLen={n}")
        if rest:
            # Для tag 3: packet_no(4) + block(2)
            if tag == 3 and len(rest) >= 6:
                pkt = le_uint(rest[0:4])
                blk = le_uint(rest[4:6])
                parts.append(f"PacketNo={pkt} Block={blk}")
            elif tag == 9 and len(rest) >= 5:
                zrep = le_uint(rest[0:2])
                ctype = rest[2]
                chk = le_uint(rest[3:5]) if len(rest) >= 5 else 0
                parts.append(f"Z={zrep} CheckType={ctype} CheckNo={chk}")
            else:
                parts.append(smart_bytes_to_text(rest))
        return " | ".join(parts)

    return smart_bytes_to_text(data)


def decode_discount(data: bytes, is_response: bool) -> str:
    """Команда 23/35 — Discount (скидка/наценка).
    Формат запроса (типичный): status(1) + amount(4, signed, bit31=sign/type) + ...
    """
    if is_response:
        if len(data) >= 4:
            val = le_uint(data[0:4], signed=True)
            # Если значение выглядит как мусор (очень большое) — показать raw
            if abs(val) > 10_000_000_00:  # > 10 млн грн
                return smart_bytes_to_text(data)
            rest = data[4:]
            s = f"Amount={money_str(val)}"
            if rest:
                t = smart_bytes_to_text(rest)
                if t:
                    s += " " + t
            return s
        return smart_bytes_to_text(data)

    if len(data) >= 5:
        status = data[0]
        amount = le_uint(data[1:5], signed=True)
        if abs(amount) > 10_000_000_00:
            return smart_bytes_to_text(data)
        rest = data[5:]
        s = f"Status={status:02X} Discount={money_str(amount)}"
        if rest:
            t = smart_bytes_to_text(rest)
            if t:
                s += " " + t
        return s
    return smart_bytes_to_text(data)


def decode_status(data: bytes, is_response: bool) -> str:
    if not is_response or len(data) < 2:
        return smart_bytes_to_text(data)

    parts = []
    conf = le_uint(data[0:2])
    flags = []
    bit_names = [
        (0, "сборы"), (1, "режим_оплат"), (2, "ящик_открыт"), (3, "чек_выплат"),
        (4, "НДС_добавляемый"), (5, "смена_открыта"), (6, "чек_открыт"),
        (9, "логотип"), (10, "запрет_обрезчика"), (11, "служебный_отчет"),
        (12, "фискализирован"), (13, "авар_завершение"), (14, "OnLine"),
    ]
    for bit, name in bit_names:
        if conf & (1 << bit):
            flags.append(name)
    parts.append(f"Flags=[{', '.join(flags) or 'нет'}]")

    pos = 2
    if pos < len(data) and data[pos] in (0x11, 0x12):
        pos += 1
    serial_end = min(pos + 19, len(data))
    serial = re.sub(r"[\x00-\x1f]", "", cp866_decode(data[pos:serial_end])).strip()
    if serial:
        parts.append(f"SN='{serial}'")
    rest = data[serial_end:]
    if rest:
        t = smart_bytes_to_text(rest)
        if t:
            parts.append(t)
    return " | ".join(parts)


def decode_comment(data: bytes, is_response: bool) -> str:
    if is_response:
        return smart_bytes_to_text(data)
    if not data:
        return "[пусто]"
    n = data[0] & 0x7F
    open_payout = bool(data[0] & 0x80)
    text = cp866_decode(data[1:1 + n]) if n else ""
    flag = " [открытие чека выплат]" if open_payout else ""
    return f"Len={n}{flag} Text='{text}'"


def decode_sale(data: bytes, is_response: bool) -> str:
    if is_response:
        if len(data) >= 8:
            cost = le_uint(data[0:4], signed=True)
            total = le_uint(data[4:8], signed=True)
            return f"Cost={money_str(cost)} TotalCheck={money_str(total)}"
        return smart_bytes_to_text(data)

    if len(data) < 10:
        return smart_bytes_to_text(data)

    qty = le_uint(data[0:3])
    status = data[3]
    decimals = status & 0x0F
    print_barcode = bool(status & 0x40)
    no_print_qty1 = bool(status & 0x80)
    price = le_uint(data[4:8], signed=True)
    tax = data[8]
    tax_ch = chr(tax) if 0x80 <= tax <= 0x85 else f"{tax:02X}"
    name_len = data[9]
    name = ""
    if name_len == 255:
        name = "[из памяти]"
    elif name_len > 0 and 10 + name_len <= len(data):
        name = cp866_decode(data[10:10 + name_len])

    flags = []
    if print_barcode:
        flags.append("штрих-код")
    if no_print_qty1:
        flags.append("не_печ_кол=1")
    flag_str = f" [{', '.join(flags)}]" if flags else ""

    return (f"Qty={qty / (10 ** decimals):.{decimals}f} "
            f"Price={money_str(price)} Tax={tax_ch} "
            f"Name='{name}'{flag_str}")


def decode_payment(data: bytes, is_response: bool) -> str:
    if is_response:
        if len(data) >= 8:
            rest = le_uint(data[0:4], signed=True)
            packet_no = le_uint(data[4:8])
            is_change = bool(rest & 0x80000000)
            rest_val = rest & 0x7FFFFFFF
            label = "Сдача" if is_change else "Остаток"
            return f"{label}={money_str(rest_val)} PacketNo={packet_no}"
        return smart_bytes_to_text(data)

    if len(data) < 6:
        return smart_bytes_to_text(data)

    status = data[0]
    pay_type = status & 0x0F
    nonfiscal = bool(status & 0x40)
    amount = le_uint(data[1:5], signed=True)
    auto_close = bool(amount & 0x80000000)
    amount_val = amount & 0x7FFFFFFF
    auth_len = data[6] if len(data) > 6 else 0
    auth = cp866_decode(data[7:7 + auth_len]) if auth_len and 7 + auth_len <= len(data) else ""

    types = {0: "наличные", 1: "карта", 2: "кредит", 3: "чек", 4: "сертификат"}
    tname = types.get(pay_type, f"тип={pay_type}")
    flags = []
    if nonfiscal:
        flags.append("нефискальный")
    if auto_close:
        flags.append("авто-закрытие")
    flag_str = f" [{', '.join(flags)}]" if flags else ""

    return f"Type={tname} Amount={money_str(amount_val)}{flag_str} Auth='{auth}'"


def decode_avans(data: bytes, is_response: bool) -> str:
    if is_response and len(data) >= 4:
        return f"PacketNo={le_uint(data[0:4])}"
    if len(data) >= 4:
        return f"Avans={money_str(le_uint(data[0:4], signed=True))}"
    return smart_bytes_to_text(data)


def decode_display_or_text(data: bytes) -> str:
    if data and 0 < data[0] < 0x40:
        n = data[0]
        if 1 + n <= len(data):
            return f"Len={n} Text='{cp866_decode(data[1:1 + n])}'"
    return f"Text='{cp866_decode(data)}'"


def decode_cmd_data(cmd: int, data: bytes, is_response: bool) -> str:
    if not data:
        return "[нет данных]"

    try:
        if cmd == 0:
            return decode_status(data, is_response)
        elif cmd == 11:
            return decode_comment(data, is_response)
        elif cmd in (12, 18):
            return decode_sale(data, is_response)
        elif cmd in (14, 20):
            return decode_payment(data, is_response)
        elif cmd == 16:
            return decode_avans(data, is_response)
        elif cmd in (23, 35):
            return decode_discount(data, is_response)
        elif cmd == 27:
            return decode_display_or_text(data)
        elif cmd == 53:
            return decode_modem_par(data, is_response)
        elif cmd in (9, 13, 15, 26, 29, 42, 43, 48):
            return f"Data: {smart_bytes_to_text(data)}"
        else:
            return f"Data: {smart_bytes_to_text(data)}"
    except Exception as e:
        return f"[ошибка разбора cmd={cmd}: {e}] Raw: {smart_bytes_to_text(data)}"


def parse_command_payload(payload: bytes, is_response: bool = False) -> str:
    if len(payload) < 3:
        return f"[слишком короткий payload: {payload.hex(' ')}]"

    seq = payload[0]
    cmd = payload[1]
    parts = [f"Seq={seq:02X}", cmd_label(cmd)]

    if is_response and len(payload) >= 6:
        status = payload[2]
        result = payload[3]
        reserve = payload[4]
        data = payload[5:-1]
        cs = payload[-1]
        parts.append(f"Status={status:02X}")
        parts.append(f"Result={result:02X}")
        if reserve != 0:
            parts.append(f"Res={reserve:02X}")
        parts.append(f"CS={cs:02X}")
        decoded = decode_cmd_data(cmd, data, is_response=True)
        parts.append(decoded)
    else:
        if len(payload) >= 3:
            params = payload[2:-1]
            cs = payload[-1]
            parts.append(f"CS={cs:02X}")
            decoded = decode_cmd_data(cmd, params, is_response=False)
            parts.append(decoded)
        else:
            parts.append(smart_bytes_to_text(payload[2:]))

    return " | ".join(parts)


# ========================= Основной обработчик строки =========================

def smart_decode_line(match: re.Match, is_rcv: bool = False) -> str:
    data_content = match.group(1)
    tokens = data_content.strip().split()
    total_bytes = len(tokens)

    # Обрезаем хвостовые нули/паддинг в токенах
    last = total_bytes - 1
    while last >= 0:
        t = tokens[last].lower()
        if t in ("0x00", "0x0", "0xff", "0x0ff"):
            last -= 1
        else:
            break
    meaningful = tokens[: last + 1] if last >= 0 else tokens

    raw = hex_tokens_to_bytes(meaningful)
    if not raw:
        # Возможно уже декодированная строка (из предыдущего прогона)
        # Просто схлопываем NUL в тексте
        collapsed = collapse_nuls_and_ctrl(data_content)
        # Подсчёт NUL
        nul_count = data_content.count("[NUL]")
        nonzero_hint = ""
        if nul_count:
            nonzero_hint = f", ненулевых≈{max(0, total_bytes - nul_count)}"
        return f"Data: {collapsed}  [Размер: {total_bytes}б{nonzero_hint}]"

    # Убираем ведущие ACK / SYN / NAK
    prefix = []
    pos = 0
    while pos < len(raw):
        if raw[pos] == 0x06:
            prefix.append("ACK")
            pos += 1
        elif raw[pos] == 0x16:
            cnt = 0
            while pos < len(raw) and raw[pos] == 0x16:
                cnt += 1
                pos += 1
            prefix.append(f"SYN×{cnt}" if cnt > 1 else "SYN")
        elif raw[pos] == 0x15:
            prefix.append("NAK")
            pos += 1
        else:
            break
    body = raw[pos:]
    nonzero = count_nonzero(body)

    packet_info = find_packet(body)
    if packet_info:
        start, end, payload = packet_info
        is_resp = is_rcv or (len(payload) >= 6 and prefix)
        decoded = parse_command_payload(payload, is_response=is_resp)
        prefix_str = " ".join(prefix) + " " if prefix else ""
        rest = body[end:]
        rest_str = f" +CRC[{rest.hex(' ')}]" if rest else ""
        size_str = f"[Размер: {total_bytes}б, ненулевых: {nonzero}]"
        return f"Data: {prefix_str}{decoded}{rest_str}  {size_str}"

    prefix_str = " ".join(prefix) + " " if prefix else ""
    text = smart_bytes_to_text(body)
    size_str = f"[Размер: {total_bytes}б, ненулевых: {nonzero}]"
    return f"Data: {prefix_str}{text}  {size_str}"


def process_file(filepath: str, output_filepath: str) -> None:
    print(f"Обработка: {filepath} → {output_filepath}")
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    new_lines = []
    for line in lines:
        if "Data:" in line:
            is_rcv = "Rcv" in line or "receive data" in line.lower()

            def make_repl(flag):
                def repl(m):
                    return smart_decode_line(m, is_rcv=flag)
                return repl

            # Поддерживаем и hex-токены, и уже частично декодированный текст
            processed = re.sub(
                r"Data:\s*(.*?)(?=\s*$|\s*\n)",
                make_repl(is_rcv),
                line.rstrip("\n"),
                count=1,
            )
            new_lines.append(processed + "\n")
        else:
            new_lines.append(line)

    with open(output_filepath, "w", encoding="utf-8") as f:
        f.writelines(new_lines)
    print(f"  OK, строк: {len(new_lines)}")


def main():
    # Обрабатываем файлы из аргументов или стандартные пути
    files = sys.argv[1:] if len(sys.argv) > 1 else []
    if not files:
        for pattern in ["*.log", "c:\\python\\decoder_log\\log\\*.log"]:
            files.extend(glob.glob(pattern))

    files = [f for f in files if "_decoded" not in os.path.basename(f) or "v2" not in f]
    if not files:
        print("Лог-файлы не найдены. Укажите путь: python decoder_iks_e810t.py file.log")
        return

    out_dir = "/home/workdir/artifacts"
    os.makedirs(out_dir, exist_ok=True)

    for f in files:
        base = os.path.basename(f)
        name, ext = os.path.splitext(base)
        out = os.path.join(out_dir, f"{name}_decoded_v2{ext}")
        try:
            process_file(f, out)
        except Exception as e:
            print(f"Ошибка {f}: {e}")


if __name__ == "__main__":
    main()
