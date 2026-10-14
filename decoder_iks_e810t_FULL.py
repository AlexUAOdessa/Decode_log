#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Декодер логов ІКС-Е810Т / ЕП-12 (EP-08).
Формат вывода близок к Claude: исходная строка + расшифровка под ней с «|».

Протокол: DLE=0x10, STX=0x02, ETX=0x03, ACK=0x06, SYN=0x16, NAK=0x15.
Текст: CP866.

Запуск:
  python decoder_iks_e810t_v2.py file.log
  python decoder_iks_e810t_v2.py          # все *.log в cwd / log/
"""

import glob
import os
import re
import sys
from typing import List, Tuple, Optional, Dict

# ========================= Справочники =========================

CMD_NAMES: Dict[int, str] = {
    0: "SendStatus — прочитать состояние регистратора",
    1: "OpenShift — открытие смены",
    2: "CloseShift — закрытие смены",
    9: "DayReport — X-отчёт",
    10: "ArtReport — отчёт по артикулам",
    11: "Comment — строка комментария / текст на чек",
    12: "Sale — регистрация продажи",
    13: "DayClrReport — Z-отчёт",
    14: "Payment — оплата",
    15: "CancelCheck / ResetOrder — отмена/обнуление чека",
    16: "Avans — служебный внос",
    17: "PeriodicReport — периодический отчёт",
    18: "Sale — регистрация продажи",
    20: "Payment — оплата / закрытие чека",
    21: "Fiscalization — фискализация",
    22: "SetHeadLine — атрибуты / заголовок",
    23: "Discount — скидка или наценка",
    24: "ServiceOut — служебная выдача",
    25: "SetTaxRate — налоговые ставки",
    26: "PeriodicReportShort — короткий периодический",
    27: "DisplayText — текст на индикатор",
    28: "GetTime — дата/время",
    29: "SetTime — установить дату/время",
    30: "PrintCopy — допечатать документ",
    31: "PeriodicReport2 — периодический по номерам",
    33: "GetBox — сумма в ящике",
    34: "ProgArt — программирование товара",
    35: "Discount — скидка или наценка",
    42: "GetDayReport — данные дневного отчёта",
    43: "GetCheckSums — данные текущего чека",
    44: "GetTaxRates — налоговые ставки",
    45: "LoadBMP — логотип",
    46: "CplCutter — обрезчик",
    47: "SetBarCode — штрих-код чека",
    48: "GetPapStat — состояние бумаги",
    49: "ArtBarCode — штрих-код артикула",
    52: "Personaliz — персонализация",
    53: "ModemPar — модем / КСЕФ / эквайер",
    54: "SetIndType — протокол индикатора",
    58: "Cmd58 — (нет в EP-08)",
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
    0: "OK / задача завершена успешно",
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

# Биты конфигурации / резерва ответа (по документации EP-08 / практике Claude)
STATUS_BITS = [
    (0, "сборы"), (1, "режим_оплат"), (2, "ящик_открыт"), (3, "чек_выплат"),
    (4, "НДС_добавляемый"), (5, "смена_открыта"), (6, "чек_открыт"),
    (9, "логотип"), (10, "запрет_обрезчика"), (11, "служебный_отчет"),
    (12, "фискализирован"), (13, "авар_завершение"), (14, "OnLine"),
]
# Для однобайтового Резерва в ответе часто: bit4=фискализирован→0x10, bit5=смена, bit6=чек
RESERVE_BITS = [
    (4, "фискализирован"), (5, "смена_открыта"), (6, "чек_открыт"),
    (1, "авария"), (2, "нет_бумаги"), (0, "принтер_не_готов"),
]

RESULT_NAMES = {
    0: "нормальное завершение",
    1: "ошибка",
    2: "закончилась бумага",
    3: "ошибка принтера",
}

PAY_TYPES = {0: "наличные", 1: "карта", 2: "кредит", 3: "чек", 4: "сертификат"}

# ========================= Утилиты =========================

def hex_tokens_to_bytes(tokens: List[str]) -> bytes:
    out = bytearray()
    for t in tokens:
        t = t.strip()
        if not t:
            continue
        if t.lower().startswith("0x"):
            try:
                out.append(int(t, 16) & 0xFF)
            except ValueError:
                pass
        else:
            # одиночный байт в виде числа или уже декодированный мусор — пропускаем
            try:
                if len(t) <= 4 and all(c in "0123456789abcdefABCDEFxX" for c in t):
                    out.append(int(t, 0) & 0xFF)
            except ValueError:
                pass
    return bytes(out)


def extract_hex_bytes(data_str: str) -> bytes:
    """Извлекает байты из строки Data: — поддерживает 0xNN и голые hex."""
    tokens = re.findall(r'0x[0-9A-Fa-f]{1,2}|(?<![0-9A-Za-z])[0-9A-Fa-f]{2}(?![0-9A-Za-z])', data_str)
    out = bytearray()
    for t in tokens:
        try:
            out.append(int(t, 16) & 0xFF)
        except ValueError:
            pass
    if out:
        return bytes(out)
    # fallback: split by space and take 0x..
    return hex_tokens_to_bytes(data_str.split())


def cp866_decode(b: bytes) -> str:
    try:
        s = b.decode("cp866", errors="replace")
    except Exception:
        s = b.decode("latin1", errors="replace")
    return "".join(c if (c.isprintable() or c in " \t") else "" for c in s).strip()


def le_uint(data: bytes, signed=False) -> int:
    if not data:
        return 0
    return int.from_bytes(data, "little", signed=signed)


def money_str(kopecks: int) -> str:
    sign = "-" if kopecks < 0 else ""
    kopecks = abs(kopecks)
    return f"{sign}{kopecks // 100}.{kopecks % 100:02d}"


def flags_from_conf(conf: int, bits=None) -> str:
    bits = bits or STATUS_BITS
    flags = []
    for bit, name in bits:
        if conf & (1 << bit):
            flags.append(name)
    return ", ".join(flags) if flags else "нет"


def find_packet(data: bytes) -> Optional[Tuple[int, int, bytes]]:
    """Ищет DLE STX ... DLE ETX, разворачивает DLE DLE."""
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


def prefix_info(raw: bytes) -> Tuple[List[str], bytes]:
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
            prefix.append(f"{cnt}xSYN" if cnt > 1 else "SYN")
        elif raw[pos] == 0x15:
            prefix.append("NAK")
            pos += 1
        else:
            break
    return prefix, raw[pos:]


# ========================= Разбор команд =========================

def decode_status(data: bytes, is_resp: bool) -> List[str]:
    lines = []
    if not is_resp or len(data) < 2:
        if data:
            lines.append(f"Data: {cp866_decode(data) or data.hex(' ')}")
        return lines
    conf = le_uint(data[0:2])
    lines.append(f"Flags=[{flags_from_conf(conf)}] (0x{conf:04X})")
    pos = 2
    if pos < len(data) and data[pos] in (0x11, 0x12):
        pos += 1
    serial_end = min(pos + 19, len(data))
    serial = cp866_decode(data[pos:serial_end])
    if serial:
        lines.append(f"SN='{serial}'")
    rest = data[serial_end:]
    # часто дальше fiscal number, attributes
    if rest:
        txt = cp866_decode(rest)
        if txt:
            lines.append(f"Info: {txt[:120]}")
    return lines


def decode_comment(data: bytes, is_resp: bool) -> List[str]:
    if is_resp:
        return []
    if not data:
        return ["[пусто]"]
    n = data[0] & 0x7F
    open_payout = bool(data[0] & 0x80)
    text = cp866_decode(data[1:1 + n]) if n else ""
    flag = " [открытие чека выплат]" if open_payout else ""
    return [f"Len={n}{flag} Text='{text}'"]


def decode_sale(data: bytes, is_resp: bool) -> List[str]:
    lines = []
    if is_resp:
        if len(data) >= 8:
            cost = le_uint(data[0:4], signed=True)
            total = le_uint(data[4:8], signed=True)
            lines.append(f"стоимость={money_str(cost)}  сумма_по_чеку={money_str(total)}")
        return lines
    if len(data) < 10:
        return [f"Raw: {data.hex(' ')}"]
    qty = le_uint(data[0:3])
    status = data[3]
    decimals = status & 0x0F
    print_barcode = bool(status & 0x40)
    no_print_qty1 = bool(status & 0x80)
    price = le_uint(data[4:8], signed=True)
    tax = data[8]
    # Налоговые группы часто кодируются как 0x80..0x85 → А..Е, либо как ASCII 'A'..'E'
    if 0x80 <= tax <= 0x85:
        tax_ch = chr(ord('А') + (tax - 0x80))
    elif 0x41 <= tax <= 0x45:  # A-E
        tax_ch = chr(tax)
    else:
        tax_ch = f"{tax:02X}"
    name_len = data[9]
    name = ""
    offset = 10
    if name_len == 255:
        name = "[из памяти]"
    elif name_len > 0 and offset + name_len <= len(data):
        name = cp866_decode(data[offset:offset + name_len])
        offset += name_len
    # УКТЗЕД / код товара (часто дальше)
    rest = data[offset:]
    uktzed = ""
    art_code = ""
    if rest:
        # типично: несколько байт + строка УКТЗЕД
        txt = cp866_decode(rest)
        # ищем последовательность цифр длины 8-10
        m = re.search(r"\d{8,10}", txt)
        if m:
            uktzed = m.group(0)
        # иногда код товара в начале rest
        if len(rest) >= 2:
            art_code = str(le_uint(rest[0:2]) if rest[0] < 0x80 else "")
    qty_f = qty / (10 ** decimals) if decimals else qty
    flags = []
    if print_barcode:
        flags.append("штрих-код")
    if no_print_qty1:
        flags.append("не_печ_кол=1")
    lines.append(f"название: «{name}»")
    lines.append(f"количество={qty_f:.{decimals}f}  статус=0x{status:02X}"
                 + (f" ({', '.join(flags)})" if flags else ""))
    lines.append(f"цена={money_str(price)}  налоговая_группа={tax_ch}")
    if uktzed:
        lines.append(f"УКТЗЕД: {uktzed}")
    return lines


def decode_payment(data: bytes, is_resp: bool) -> List[str]:
    lines = []
    if is_resp:
        if len(data) >= 8:
            rest = le_uint(data[0:4], signed=True)
            packet_no = le_uint(data[4:8])
            is_change = bool(rest & 0x80000000)
            rest_val = rest & 0x7FFFFFFF
            label = "сдача" if is_change else "остаток_к_оплате"
            lines.append(f"{label}={money_str(rest_val)}  номер_пакета_КЛЕФ={packet_no}")
            if packet_no and rest_val == 0:
                lines.append("-> ЧЕК ЗАКРЫТ И ЗАРЕГИСТРИРОВАН")
        # URL в ответе
        txt = cp866_decode(data)
        if "https://" in txt or "cabinet.tax" in txt:
            url = re.search(r"https?://[^\s\x00]+", txt)
            if url:
                lines.append(url.group(0))
        return lines
    if len(data) < 6:
        return [f"Raw: {data.hex(' ')}"]
    status = data[0]
    pay_type = status & 0x0F
    nonfiscal = bool(status & 0x40)
    amount = le_uint(data[1:5], signed=True)
    auto_close = bool(amount & 0x80000000)
    amount_val = amount & 0x7FFFFFFF
    auth_len = data[6] if len(data) > 6 else 0
    auth = cp866_decode(data[7:7 + auth_len]) if auth_len and 7 + auth_len <= len(data) else ""
    tname = PAY_TYPES.get(pay_type, f"тип={pay_type}")
    flags = []
    if nonfiscal:
        flags.append("нефискальный")
    if auto_close:
        flags.append("авто-закрытие")
    flag_str = f" [{', '.join(flags)}]" if flags else ""
    lines.append(f"Type={tname} Amount={money_str(amount_val)}{flag_str}")
    if auth:
        lines.append(f"Auth/RRN='{auth}'")
    return lines


def decode_discount(data: bytes, is_resp: bool) -> List[str]:
    if is_resp:
        if len(data) >= 4:
            val = le_uint(data[0:4], signed=True)
            if abs(val) < 10_000_000_00:
                return [f"Amount={money_str(val)}"]
        return []
    if len(data) >= 5:
        status = data[0]
        amount = le_uint(data[1:5], signed=True)
        if abs(amount) < 10_000_000_00:
            return [f"Status=0x{status:02X} Discount={money_str(amount)}"]
    return [f"Raw: {data.hex(' ')}"]


def decode_modem_par(data: bytes, is_resp: bool) -> List[str]:
    lines = []
    if not data:
        return ["[нет данных]"]
    if is_resp:
        if len(data) >= 3:
            code = data[0]
            n = le_uint(data[1:3])
            payload = data[3:3 + n] if n else b""
            err = MODEM_ERR.get(code, f"код={code}")
            lines.append(f"код_результата_модема={code} ({err})")
            if n:
                lines.append(f"длина_данных={n}")
            if payload:
                # номер пакета КСЕФ (4 байта LE)
                if n == 4:
                    lines.append(f"номер_пакета_КСЕФ={le_uint(payload)}")
                else:
                    txt = cp866_decode(payload)
                    if txt and len(txt) > 3:
                        lines.append(f"Data: {txt[:100]}")
                    elif n <= 20:
                        lines.append(f"Raw: {payload.hex(' ')}")
                    else:
                        lines.append("структура состояния модема (формат в док. не раскрыт)")
        return lines
    # request
    if len(data) >= 5:
        n = le_uint(data[2:4])
        tag = data[4]
        tag_name = MODEM_TAGS.get(tag, f"tag={tag}")
        rest = data[5:5 + max(0, n - 1)] if n else data[5:]
        lines.append(f"длина_параметров={n}  таг={tag} ({tag_name})")
        if tag == 3 and len(rest) >= 6:
            pkt = le_uint(rest[0:4])
            blk = le_uint(rest[4:6])
            lines.append(f"номер_пакета_КСЕФ={pkt}  номер_блока={blk}")
        elif tag == 9 and len(rest) >= 5:
            zrep = le_uint(rest[0:2])
            ctype = rest[2]
            chk = le_uint(rest[3:5])
            lines.append(f"номер_Z={zrep}  тип_чека={ctype}  номер_чека={chk}")
        elif rest:
            txt = cp866_decode(rest)
            if txt:
                lines.append(txt[:80])
    return lines


def decode_display(data: bytes) -> List[str]:
    if data and 0 < data[0] < 0x40:
        n = data[0]
        if 1 + n <= len(data):
            return [f"Len={n} Text='{cp866_decode(data[1:1+n])}'"]
    return [f"Text='{cp866_decode(data)}'"]


def decode_avans(data: bytes, is_resp: bool) -> List[str]:
    if is_resp and len(data) >= 4:
        return [f"PacketNo={le_uint(data[0:4])}"]
    if len(data) >= 4:
        return [f"Avans={money_str(le_uint(data[0:4], signed=True))}"]
    return []


def decode_cmd_data(cmd: int, data: bytes, is_resp: bool) -> List[str]:
    if not data and cmd not in (0, 9, 13, 15):
        return ["[нет данных]"]
    try:
        if cmd == 0:
            return decode_status(data, is_resp)
        if cmd == 11:
            return decode_comment(data, is_resp)
        if cmd in (12, 18):
            return decode_sale(data, is_resp)
        if cmd in (14, 20):
            return decode_payment(data, is_resp)
        if cmd == 16:
            return decode_avans(data, is_resp)
        if cmd in (23, 35):
            return decode_discount(data, is_resp)
        if cmd == 27:
            return decode_display(data)
        if cmd == 53:
            return decode_modem_par(data, is_resp)
        if cmd in (9, 13, 15, 24, 29, 42, 43, 48):
            if data:
                txt = cp866_decode(data)
                if txt:
                    return [f"Data: {txt[:100]}"]
                if len(data) <= 16:
                    return [f"Raw: {data.hex(' ')}"]
                # GetDayReport — большие структуры
                if cmd == 42 and len(data) > 20:
                    return [f"структура дневного отчёта, {len(data)} байт"]
            return []
        # fallback
        txt = cp866_decode(data)
        if txt and len(txt) > 2:
            return [f"Data: {txt[:100]}"]
        if data and len(data) <= 24:
            return [f"Raw: {data.hex(' ')}"]
        return [f"[{len(data)} байт]"]
    except Exception as e:
        return [f"[ошибка разбора: {e}]"]


def parse_payload(payload: bytes, is_resp: bool) -> List[str]:
    """Возвращает список строк расшифровки для payload кадра."""
    lines = []
    if len(payload) < 2:
        lines.append(f"[короткий payload: {payload.hex(' ')}]")
        return lines
    seq = payload[0]
    cmd = payload[1]
    name = CMD_NAMES.get(cmd, f"Cmd={cmd}")
    direction = "ОТВЕТ  " if is_resp else "КОМАНДА"
    lines.append(f"{direction} Код {cmd} — {name}   Номер=0x{seq:02X}")

    if is_resp and len(payload) >= 5:
        status = payload[2]
        result = payload[3]
        reserve = payload[4]
        data = payload[5:-1] if len(payload) > 5 else b""
        cs = payload[-1] if len(payload) > 5 else None
        st_bits = []
        if status & 0x01:
            st_bits.append("принтер не готов")
        if status & 0x80:
            st_bits.append("команда запрещена/не существует в режиме")
        st_s = f" [{', '.join(st_bits)}]" if st_bits else " [нет]"
        lines.append(f"Статус=0x{status:02X}{st_s}")
        res_name = RESULT_NAMES.get(result, str(result))
        lines.append(f"Результат={result} [{res_name}]")
        lines.append(f"Резерв=0x{reserve:02X} [{flags_from_conf(reserve, RESERVE_BITS)}]")
        if cs is not None:
            lines.append(f"CS=0x{cs:02X}")
        lines.extend(decode_cmd_data(cmd, data, is_resp=True))
    else:
        params = payload[2:-1] if len(payload) > 3 else payload[2:]
        cs = payload[-1] if len(payload) > 2 else None
        if cs is not None:
            lines.append(f"CS=0x{cs:02X}")
        lines.extend(decode_cmd_data(cmd, params, is_resp=False))
    return lines


def decode_data_line(data_str: str, is_rcv: bool) -> List[str]:
    """Главная точка: строка после Data: → список строк | расшифровки."""
    raw = extract_hex_bytes(data_str)
    if not raw:
        # уже частично декодировано — схлопнем NUL
        collapsed = re.sub(r"(?:\[NUL\]){2,}", lambda m: f"[NUL×{m.group(0).count('[NUL]')}]", data_str)
        return [f"Data: {collapsed.strip()[:150]}"]

    prefix, body = prefix_info(raw)
    out = []
    if prefix:
        out.append(f"перед кадром: {', '.join(prefix)}")

    pkt = find_packet(body)
    if pkt:
        start, end, payload = pkt
        is_resp = is_rcv or bool(prefix)
        out.extend(parse_payload(payload, is_resp=is_resp))
        rest = body[end:]
        if rest and any(b != 0 for b in rest):
            # CRC16 часто 2 байта
            if len(rest) == 2:
                out.append(f"CRC16=0x{rest[0]:02X}{rest[1]:02X}")
            else:
                out.append(f"+хвост {rest.hex(' ')}")
    else:
        txt = cp866_decode(body)
        if txt:
            out.append(f"Data: {txt[:120]}")
        else:
            out.append(f"Raw: {body[:40].hex(' ')}...")
    return out


# ========================= Обработка файла =========================

def process_file(filepath: str, output_filepath: str) -> None:
    print(f"Обработка: {filepath}")
    print(f"  → {output_filepath}")
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    new_lines: List[str] = []
    stats = {"snd": 0, "rcv": 0, "cmds": {}}

    for line in lines:
        raw_line = line.rstrip("\n")
        new_lines.append(raw_line + "\n")

        if "Data:" not in raw_line and "WAITING" not in raw_line and "PORT" not in raw_line:
            continue

        is_rcv = "Rcv" in raw_line or "receive data" in raw_line.lower()
        is_snd = "Snd" in raw_line

        if "WAITING" in raw_line:
            new_lines.append("       | ПО ждёт ответа (ЭККР может слать SYN)\n")
            continue

        m = re.search(r"Data:\s*(.*)$", raw_line)
        if not m:
            continue

        data_content = m.group(1)
        try:
            decoded = decode_data_line(data_content, is_rcv=is_rcv)
        except Exception as e:
            decoded = [f"[ошибка: {e}]"]

        for d in decoded:
            new_lines.append(f"       | {d}\n")

        if is_snd:
            stats["snd"] += 1
        if is_rcv:
            stats["rcv"] += 1
        # cmd id from func ID =
        fm = re.search(r"func ID\s*=\s*(\d+)", raw_line)
        if fm:
            c = int(fm.group(1))
            stats["cmds"][c] = stats["cmds"].get(c, 0) + 1

    # заголовок
    header = [
        "РАСШИФРОВКА ЛОГА ОБМЕНА ПК <-> ЭККР ІКС-Е810Т\n",
        "=" * 80 + "\n",
        f"Исходный файл : {os.path.basename(filepath)}\n",
        f"Строк исходных: {len(lines)}\n",
        f"Snd: {stats['snd']}  Rcv: {stats['rcv']}\n",
        "Команды (по func ID):\n",
    ]
    for c in sorted(stats["cmds"].keys()):
        name = CMD_NAMES.get(c, "")
        header.append(f"  Код {c:3d}  {stats['cmds'][c]:5d}   {name}\n")
    header.append("=" * 80 + "\n")
    header.append("Исходные строки сохранены. Расшифровка добавлена под Data: с префиксом «|».\n")
    header.append("=" * 80 + "\n\n")

    with open(output_filepath, "w", encoding="utf-8") as f:
        f.writelines(header)
        f.writelines(new_lines)
    print(f"  OK, строк выхода: {len(header) + len(new_lines)}")


def main():
    files = sys.argv[1:] if len(sys.argv) > 1 else []
    if not files:
        files = sorted(glob.glob("*.log")) + sorted(glob.glob("log/*.log"))
        files = [f for f in files if "_decoded" not in os.path.basename(f).lower()]

    if not files:
        print("Укажите .log файл: python decoder_iks_e810t_v2.py file.log")
        return

    out_dir = "Decod_log"
    os.makedirs(out_dir, exist_ok=True)

    for f in files:
        if not os.path.isfile(f):
            print(f"Нет файла: {f}")
            continue
        base = os.path.basename(f)
        name, ext = os.path.splitext(base)
        out = os.path.join(out_dir, f"{name}_decoded_v2{ext}")
        try:
            process_file(f, out)
        except Exception as e:
            print(f"Ошибка {f}: {e}")
            import traceback
            traceback.print_exc()
    print("Готово.")


if __name__ == "__main__":
    main()
