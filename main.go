// Декодер логов ІКС-Е810Т / ЕП-12 (EP-08).
// Формат вывода: исходная строка + расшифровка под ней с «|».
//
// Протокол: DLE=0x10, STX=0x02, ETX=0x03, ACK=0x06, SYN=0x16, NAK=0x15.
// Текст: CP866.
//
// Запуск:
//
//	go run . file.log
//	go run .              # все *.log в cwd / log/
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ========================= Справочники =========================

var cmdNames = map[int]string{
	0:  "SendStatus — прочитать состояние регистратора",
	1:  "OpenShift — открытие смены",
	2:  "CloseShift — закрытие смены",
	9:  "DayReport — X-отчёт",
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

var modemTags = map[int]string{
	1:  "инициировать обмен с эквайером",
	2:  "безусловный обмен с эквайером",
	3:  "получить пакет КСЕФ",
	4:  "состояние модема (структура)",
	5:  "состояние модема (текст)",
	8:  "проверить пакет КСЕФ",
	9:  "получить номер пакета КСЕФ",
	10: "текущая задача модема",
}

var modemErr = map[int]string{
	0:   "OK / задача завершена успешно",
	1:   "общая ошибка модема",
	2:   "таймаут старта задачи",
	3:   "нет записи персонализации в КСЕФ",
	4:   "ошибка служебной области КСЕФ",
	5:   "ошибка записи КСЕФ",
	6:   "ошибка создания пакета КСЕФ",
	7:   "ошибка чтения пакета КСЕФ",
	8:   "РРО не фискализирован",
	9:   "ошибка данных от фискального блока",
	10:  "КСЕФ заполнен",
	11:  "неверный номер пакета КСЕФ",
	12:  "ошибка подписи пакета КСЕФ",
	13:  "SAM занят",
	14:  "ошибка SAM",
	15:  "данные КСЕФ повреждены",
	16:  "неизвестный код команды",
	251: "команда не может быть выполнена",
	252: "модем занят",
	253: "внутренняя ошибка модема",
	254: "таймаут считывания ФБ",
	255: "общая ошибка модема",
}

type bitName struct {
	bit  int
	name string
}

var statusBits = []bitName{
	{0, "сборы"}, {1, "режим_оплат"}, {2, "ящик_открыт"}, {3, "чек_выплат"},
	{4, "НДС_добавляемый"}, {5, "смена_открыта"}, {6, "чек_открыт"},
	{9, "логотип"}, {10, "запрет_обрезчика"}, {11, "служебный_отчет"},
	{12, "фискализирован"}, {13, "авар_завершение"}, {14, "OnLine"},
}

var reserveBits = []bitName{
	{4, "фискализирован"}, {5, "смена_открыта"}, {6, "чек_открыт"},
	{1, "авария"}, {2, "нет_бумаги"}, {0, "принтер_не_готов"},
}

var resultNames = map[int]string{
	0: "нормальное завершение",
	1: "ошибка",
	2: "закончилась бумага",
	3: "ошибка принтера",
}

var payTypes = map[int]string{
	0: "наличные", 1: "карта", 2: "кредит", 3: "чек", 4: "сертификат",
}

// CP866 → Unicode (базовая таблица для кириллицы)
var cp866Table [256]rune
var cp1251Table [256]rune

func init() {
	for i := 0; i < 128; i++ {
		cp866Table[i] = rune(i)
	}
	// Cyrillic А-Я (0x80-0x9F)
	cyrUpper := []rune("АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ")
	for i, r := range cyrUpper {
		cp866Table[0x80+i] = r
	}
	// а-п (0xA0-0xAF)
	cyrLower1 := []rune("абвгдежзийклмноп")
	for i, r := range cyrLower1 {
		cp866Table[0xA0+i] = r
	}
	// р-я (0xE0-0xEF)
	cyrLower2 := []rune("рстуфхцчшщъыьэюя")
	for i, r := range cyrLower2 {
		cp866Table[0xE0+i] = r
	}
	cp866Table[0xF0] = 'Ё'
	cp866Table[0xF1] = 'ё'
	// box drawing / extras often appear as-is; leave 0xB0-0xDF as latin1-ish
	for i := 0xB0; i <= 0xDF; i++ {
		cp866Table[i] = rune(i)
	}

	// Windows-1251
	for i := 0; i < 128; i++ {
		cp1251Table[i] = rune(i)
	}
	// Cyrillic in 1251: 0xC0-0xFF = А-я
	cyr1251 := []rune("АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя")
	for i, r := range cyr1251 {
		cp1251Table[0xC0+i] = r
	}
	cp1251Table[0xA8] = 'Ё'
	cp1251Table[0xB8] = 'ё'
	cp1251Table[0xB9] = '№'
}

// ========================= Утилиты =========================

var (
	reHexToken = regexp.MustCompile(`(?i)0x[0-9A-Fa-f]{1,2}|\b[0-9A-Fa-f]{2}\b`)
	reURL      = regexp.MustCompile(`https?://[^\s\x00]+`)
	reDigits   = regexp.MustCompile(`\d{8,10}`)
	reData     = regexp.MustCompile(`Data:\s*(.*)$`)
	reFuncID   = regexp.MustCompile(`func ID\s*=\s*(\d+)`)
	reNUL      = regexp.MustCompile(`(?:\[NUL\]){2,}`)
)

func extractHexBytes(dataStr string) []byte {
	tokens := reHexToken.FindAllString(dataStr, -1)
	out := make([]byte, 0, len(tokens))
	for _, t := range tokens {
		v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(t), "0x"), 16, 8)
		if err == nil {
			out = append(out, byte(v))
		}
	}
	if len(out) > 0 {
		return out
	}
	// fallback: split by space
	for _, t := range strings.Fields(dataStr) {
		t = strings.TrimSpace(t)
		if strings.HasPrefix(strings.ToLower(t), "0x") {
			v, err := strconv.ParseUint(t[2:], 16, 8)
			if err == nil {
				out = append(out, byte(v))
			}
		}
	}
	return out
}

func cp866Decode(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		r := cp866Table[c]
		if unicode.IsPrint(r) || r == ' ' || r == '\t' {
			sb.WriteRune(r)
		}
	}
	return strings.TrimSpace(sb.String())
}

func leUint(data []byte, signed bool) int64 {
	if len(data) == 0 {
		return 0
	}
	// pad to 8 for simplicity
	buf := make([]byte, 8)
	copy(buf, data)
	if signed {
		n := int(len(data))
		if n > 0 && data[n-1]&0x80 != 0 {
			for i := n; i < 8; i++ {
				buf[i] = 0xFF
			}
		}
		return int64(binary.LittleEndian.Uint64(buf))
	}
	return int64(binary.LittleEndian.Uint64(buf))
}

func moneyStr(kopecks int64) string {
	sign := ""
	if kopecks < 0 {
		sign = "-"
		kopecks = -kopecks
	}
	return fmt.Sprintf("%s%d.%02d", sign, kopecks/100, kopecks%100)
}

func flagsFromConf(conf int, bits []bitName) string {
	var flags []string
	for _, bn := range bits {
		if conf&(1<<bn.bit) != 0 {
			flags = append(flags, bn.name)
		}
	}
	if len(flags) == 0 {
		return "нет"
	}
	return strings.Join(flags, ", ")
}

type packetInfo struct {
	start, end int
	payload    []byte
}

func findPacket(data []byte) *packetInfo {
	for i := 0; i < len(data)-3; i++ {
		if data[i] == 0x10 && data[i+1] == 0x02 {
			payload := make([]byte, 0, 64)
			j := i + 2
			for j < len(data)-1 {
				if data[j] == 0x10 && data[j+1] == 0x03 {
					return &packetInfo{i, j + 2, payload}
				}
				if data[j] == 0x10 && j+1 < len(data) && data[j+1] == 0x10 {
					payload = append(payload, 0x10)
					j += 2
				} else {
					payload = append(payload, data[j])
					j++
				}
			}
			break
		}
	}
	return nil
}

func prefixInfo(raw []byte) (prefix []string, body []byte) {
	pos := 0
	for pos < len(raw) {
		switch raw[pos] {
		case 0x06:
			prefix = append(prefix, "ACK")
			pos++
		case 0x16:
			cnt := 0
			for pos < len(raw) && raw[pos] == 0x16 {
				cnt++
				pos++
			}
			if cnt > 1 {
				prefix = append(prefix, fmt.Sprintf("%dxSYN", cnt))
			} else {
				prefix = append(prefix, "SYN")
			}
		case 0x15:
			prefix = append(prefix, "NAK")
			pos++
		default:
			return prefix, raw[pos:]
		}
	}
	return prefix, raw[pos:]
}

// ========================= Разбор команд =========================

func decodeStatus(data []byte, isResp bool) []string {
	var lines []string
	if !isResp || len(data) < 2 {
		if len(data) > 0 {
			t := cp866Decode(data)
			if t == "" {
				t = fmt.Sprintf("% x", data)
			}
			lines = append(lines, "Data: "+t)
		}
		return lines
	}
	conf := int(leUint(data[0:2], false))
	lines = append(lines, fmt.Sprintf("Flags=[%s] (0x%04X)", flagsFromConf(conf, statusBits), conf))
	pos := 2
	if pos < len(data) && (data[pos] == 0x11 || data[pos] == 0x12) {
		pos++
	}
	serialEnd := pos + 19
	if serialEnd > len(data) {
		serialEnd = len(data)
	}
	serial := cp866Decode(data[pos:serialEnd])
	if serial != "" {
		lines = append(lines, fmt.Sprintf("SN='%s'", serial))
	}
	rest := data[serialEnd:]
	if len(rest) > 0 {
		txt := cp866Decode(rest)
		if txt != "" {
			txt = safeTruncate(txt, 120)
			lines = append(lines, "Info: "+txt)
		}
	}
	return lines
}

func decodeComment(data []byte, isResp bool) []string {
	if isResp {
		return nil
	}
	if len(data) == 0 {
		return []string{"[пусто]"}
	}
	n := int(data[0] & 0x7F)
	openPayout := data[0]&0x80 != 0
	text := ""
	if n > 0 && 1+n <= len(data) {
		text = cp866Decode(data[1 : 1+n])
	}
	flag := ""
	if openPayout {
		flag = " [открытие чека выплат]"
	}
	return []string{fmt.Sprintf("Len=%d%s Text='%s'", n, flag, text)}
}

func decodeSale(data []byte, isResp bool) []string {
	var lines []string
	if isResp {
		if len(data) >= 8 {
			cost := leUint(data[0:4], true)
			total := leUint(data[4:8], true)
			lines = append(lines, fmt.Sprintf("стоимость=%s  сумма_по_чеку=%s", moneyStr(cost), moneyStr(total)))
		}
		return lines
	}
	if len(data) < 10 {
		return []string{fmt.Sprintf("Raw: % x", data)}
	}
	qty := leUint(data[0:3], false)
	status := data[3]
	decimals := int(status & 0x0F)
	printBarcode := status&0x40 != 0
	noPrintQty1 := status&0x80 != 0
	price := leUint(data[4:8], true)
	tax := data[8]
	var taxCh string
	switch {
	case tax >= 0x80 && tax <= 0x85:
		taxCh = string(rune('А') + rune(tax-0x80))
	case tax >= 0x41 && tax <= 0x45:
		taxCh = string(tax)
	default:
		taxCh = fmt.Sprintf("%02X", tax)
	}
	nameLen := int(data[9])
	name := ""
	offset := 10
	if nameLen == 255 {
		name = "[из памяти]"
	} else if nameLen > 0 && offset+nameLen <= len(data) {
		name = cp866Decode(data[offset : offset+nameLen])
		offset += nameLen
	}
	rest := data[offset:]
	uktzed := ""
	if len(rest) > 0 {
		txt := cp866Decode(rest)
		if m := reDigits.FindString(txt); m != "" {
			uktzed = m
		}
	}
	var qtyF float64
	if decimals > 0 {
		div := 1.0
		for i := 0; i < decimals; i++ {
			div *= 10
		}
		qtyF = float64(qty) / div
	} else {
		qtyF = float64(qty)
	}
	var flags []string
	if printBarcode {
		flags = append(flags, "штрих-код")
	}
	if noPrintQty1 {
		flags = append(flags, "не_печ_кол=1")
	}
	lines = append(lines, fmt.Sprintf("название: «%s»", name))
	flagStr := ""
	if len(flags) > 0 {
		flagStr = " (" + strings.Join(flags, ", ") + ")"
	}
	fmtQty := fmt.Sprintf("%.*f", decimals, qtyF)
	lines = append(lines, fmt.Sprintf("количество=%s  статус=0x%02X%s", fmtQty, status, flagStr))
	lines = append(lines, fmt.Sprintf("цена=%s  налоговая_группа=%s", moneyStr(price), taxCh))
	if uktzed != "" {
		lines = append(lines, "УКТЗЕД: "+uktzed)
	}
	return lines
}

func decodePayment(data []byte, isResp bool) []string {
	var lines []string
	if isResp {
		if len(data) >= 8 {
			rest := leUint(data[0:4], true)
			packetNo := leUint(data[4:8], false)
			isChange := rest&0x80000000 != 0
			restVal := rest & 0x7FFFFFFF
			label := "остаток_к_оплате"
			if isChange {
				label = "сдача"
			}
			lines = append(lines, fmt.Sprintf("%s=%s  номер_пакета_КЛЕФ=%d", label, moneyStr(restVal), packetNo))
			if packetNo != 0 && restVal == 0 {
				lines = append(lines, "-> ЧЕК ЗАКРЫТ И ЗАРЕГИСТРИРОВАН")
			}
		}
		txt := cp866Decode(data)
		if strings.Contains(txt, "https://") || strings.Contains(txt, "cabinet.tax") {
			if m := reURL.FindString(txt); m != "" {
				lines = append(lines, m)
			}
		}
		return lines
	}
	if len(data) < 6 {
		return []string{fmt.Sprintf("Raw: % x", data)}
	}
	status := data[0]
	payType := int(status & 0x0F)
	nonfiscal := status&0x40 != 0
	amount := leUint(data[1:5], true)
	autoClose := amount&0x80000000 != 0
	amountVal := amount & 0x7FFFFFFF
	authLen := 0
	if len(data) > 6 {
		authLen = int(data[6])
	}
	auth := ""
	if authLen > 0 && 7+authLen <= len(data) {
		auth = cp866Decode(data[7 : 7+authLen])
	}
	tname, ok := payTypes[payType]
	if !ok {
		tname = fmt.Sprintf("тип=%d", payType)
	}
	var flags []string
	if nonfiscal {
		flags = append(flags, "нефискальный")
	}
	if autoClose {
		flags = append(flags, "авто-закрытие")
	}
	flagStr := ""
	if len(flags) > 0 {
		flagStr = " [" + strings.Join(flags, ", ") + "]"
	}
	lines = append(lines, fmt.Sprintf("Type=%s Amount=%s%s", tname, moneyStr(amountVal), flagStr))
	if auth != "" {
		lines = append(lines, fmt.Sprintf("Auth/RRN='%s'", auth))
	}
	return lines
}

func decodeDiscount(data []byte, isResp bool) []string {
	if isResp {
		if len(data) >= 4 {
			val := leUint(data[0:4], true)
			if abs64(val) < 10_000_000_00 {
				return []string{fmt.Sprintf("Amount=%s", moneyStr(val))}
			}
		}
		return nil
	}
	if len(data) >= 5 {
		status := data[0]
		amount := leUint(data[1:5], true)
		if abs64(amount) < 10_000_000_00 {
			return []string{fmt.Sprintf("Status=0x%02X Discount=%s", status, moneyStr(amount))}
		}
	}
	return []string{fmt.Sprintf("Raw: % x", data)}
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// printableRatio — доля печатных символов после CP866 (для отсечения бинарного мусора).
func printableRatio(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	ok := 0
	for _, c := range b {
		if c == 0 {
			continue
		}
		r := cp866Table[c]
		if (r >= 32 && r < 127) || (r >= 0x400 && r < 0x500) {
			ok++
		}
	}
	nonzero := 0
	for _, c := range b {
		if c != 0 {
			nonzero++
		}
	}
	if nonzero == 0 {
		return 0
	}
	return float64(ok) / float64(nonzero)
}

// extractPrintableRuns — только читаемые фрагменты CP866, без бинарного шума.
func extractPrintableRuns(b []byte) string {
	var parts []string
	var cur []rune
	flush := func() {
		if len(cur) >= 3 {
			parts = append(parts, string(cur))
		}
		cur = cur[:0]
	}
	for _, c := range b {
		if c == 0 {
			flush()
			continue
		}
		r := cp866Table[c]
		if (r >= 32 && r < 127) || (r >= 0x400 && r < 0x500) || r == 'ё' || r == 'Ё' || r == '№' {
			cur = append(cur, r)
		} else {
			flush()
		}
	}
	flush()
	if len(parts) == 0 {
		return ""
	}
	out := strings.Join(parts, " | ")
	return safeTruncate(out, 120)
}

func decodeModemPar(data []byte, isResp bool) []string {
	var lines []string
	if len(data) == 0 {
		return []string{"[нет данных]"}
	}
	if isResp {
		if len(data) >= 3 {
			code := int(data[0])
			n := int(leUint(data[1:3], false))
			var payload []byte
			if n > 0 && 3+n <= len(data) {
				payload = data[3 : 3+n]
			} else if n > 0 {
				payload = data[3:]
			}
			err, ok := modemErr[code]
			if !ok {
				err = fmt.Sprintf("код=%d", code)
			}
			lines = append(lines, fmt.Sprintf("код_результата_модема=%d (%s)", code, err))
			if n > 0 {
				lines = append(lines, fmt.Sprintf("длина_данных=%d", n))
			}
			if len(payload) > 0 {
				if n == 4 {
					lines = append(lines, fmt.Sprintf("номер_пакета_КСЕФ=%d", leUint(payload, false)))
				} else if n >= 100 && printableRatio(payload) < 0.45 {
					// бинарная структура модема / служебные блоки — не гоняем через CP866
					lines = append(lines, fmt.Sprintf("бинарные данные %d байт (структура модема/КСЕФ, не текст)", n))
				} else {
					txt := extractPrintableRuns(payload)
					if txt != "" {
						lines = append(lines, "Текст: "+txt)
					} else if n <= 16 {
						lines = append(lines, fmt.Sprintf("Raw: % x", payload))
					} else {
						lines = append(lines, fmt.Sprintf("бинарные данные %d байт", n))
					}
				}
			}
		}
		return lines
	}
	if len(data) >= 5 {
		n := int(leUint(data[2:4], false))
		tag := int(data[4])
		tagName, ok := modemTags[tag]
		if !ok {
			tagName = fmt.Sprintf("tag=%d", tag)
		}
		var rest []byte
		if n > 0 {
			end := 5 + max(0, n-1)
			if end > len(data) {
				end = len(data)
			}
			rest = data[5:end]
		} else {
			rest = data[5:]
		}
		lines = append(lines, fmt.Sprintf("длина_параметров=%d  таг=%d (%s)", n, tag, tagName))
		if tag == 3 && len(rest) >= 6 {
			pkt := leUint(rest[0:4], false)
			blk := leUint(rest[4:6], false)
			lines = append(lines, fmt.Sprintf("номер_пакета_КСЕФ=%d  номер_блока=%d", pkt, blk))
		} else if tag == 9 && len(rest) >= 5 {
			zrep := leUint(rest[0:2], false)
			ctype := rest[2]
			chk := leUint(rest[3:5], false)
			lines = append(lines, fmt.Sprintf("номер_Z=%d  тип_чека=%d  номер_чека=%d", zrep, ctype, chk))
		} else if len(rest) > 0 {
			txt := cp866Decode(rest)
			if txt != "" {
				txt = safeTruncate(txt, 80)
				lines = append(lines, txt)
			}
		}
	}
	return lines
}

func decodeDisplay(data []byte) []string {
	if len(data) > 0 && data[0] > 0 && data[0] < 0x40 {
		n := int(data[0])
		if 1+n <= len(data) {
			return []string{fmt.Sprintf("Len=%d Text='%s'", n, cp866Decode(data[1:1+n]))}
		}
	}
	return []string{fmt.Sprintf("Text='%s'", cp866Decode(data))}
}

func decodeAvans(data []byte, isResp bool) []string {
	if isResp && len(data) >= 4 {
		return []string{fmt.Sprintf("PacketNo=%d", leUint(data[0:4], false))}
	}
	if len(data) >= 4 {
		return []string{fmt.Sprintf("Avans=%s", moneyStr(leUint(data[0:4], true)))}
	}
	return nil
}

func decodeCmdData(cmd int, data []byte, isResp bool) []string {
	if len(data) == 0 && cmd != 0 && cmd != 9 && cmd != 13 && cmd != 15 {
		return []string{"[нет данных]"}
	}
	defer func() {
		_ = recover() // safety for edge cases
	}()
	switch cmd {
	case 0:
		return decodeStatus(data, isResp)
	case 11:
		return decodeComment(data, isResp)
	case 12, 18:
		return decodeSale(data, isResp)
	case 14, 20:
		return decodePayment(data, isResp)
	case 16:
		return decodeAvans(data, isResp)
	case 23, 35:
		return decodeDiscount(data, isResp)
	case 27:
		return decodeDisplay(data)
	case 53:
		return decodeModemPar(data, isResp)
	case 9, 13, 15, 24, 29, 42, 43, 48:
		if len(data) > 0 {
			txt := cp866Decode(data)
			if txt != "" {
				txt = safeTruncate(txt, 100)
				return []string{"Data: " + txt}
			}
			if len(data) <= 16 {
				return []string{fmt.Sprintf("Raw: % x", data)}
			}
			if cmd == 42 && len(data) > 20 {
				return []string{fmt.Sprintf("структура дневного отчёта, %d байт", len(data))}
			}
		}
		return nil
	default:
		txt := cp866Decode(data)
		if txt != "" && len(txt) > 2 {
			txt = safeTruncate(txt, 100)
			return []string{"Data: " + txt}
		}
		if len(data) > 0 && len(data) <= 24 {
			return []string{fmt.Sprintf("Raw: % x", data)}
		}
		if len(data) > 0 {
			return []string{fmt.Sprintf("[%d байт]", len(data))}
		}
		return nil
	}
}

func parsePayload(payload []byte, isResp bool) []string {
	var lines []string
	if len(payload) < 2 {
		lines = append(lines, fmt.Sprintf("[короткий payload: % x]", payload))
		return lines
	}
	seq := int(payload[0])
	cmd := int(payload[1])
	name, ok := cmdNames[cmd]
	if !ok {
		name = fmt.Sprintf("Cmd=%d", cmd)
	}
	direction := "КОМАНДА"
	if isResp {
		direction = "ОТВЕТ  "
	}
	lines = append(lines, fmt.Sprintf("%s Код %d — %s   Номер=0x%02X", direction, cmd, name, seq))

	if isResp && len(payload) >= 5 {
		status := payload[2]
		result := int(payload[3])
		reserve := int(payload[4])
		var data []byte
		var cs byte
		hasCS := false
		if len(payload) > 5 {
			data = payload[5 : len(payload)-1]
			cs = payload[len(payload)-1]
			hasCS = true
		}
		var stBits []string
		if status&0x01 != 0 {
			stBits = append(stBits, "принтер не готов")
		}
		if status&0x80 != 0 {
			stBits = append(stBits, "команда запрещена/не существует в режиме")
		}
		stS := " [нет]"
		if len(stBits) > 0 {
			stS = " [" + strings.Join(stBits, ", ") + "]"
		}
		lines = append(lines, fmt.Sprintf("Статус=0x%02X%s", status, stS))
		resName, ok := resultNames[result]
		if !ok {
			resName = strconv.Itoa(result)
		}
		lines = append(lines, fmt.Sprintf("Результат=%d [%s]", result, resName))
		lines = append(lines, fmt.Sprintf("Резерв=0x%02X [%s]", reserve, flagsFromConf(reserve, reserveBits)))
		if hasCS {
			lines = append(lines, fmt.Sprintf("CS=0x%02X", cs))
		}
		lines = append(lines, decodeCmdData(cmd, data, true)...)
	} else {
		var params []byte
		var cs byte
		hasCS := false
		if len(payload) > 3 {
			params = payload[2 : len(payload)-1]
			cs = payload[len(payload)-1]
			hasCS = true
		} else if len(payload) > 2 {
			params = payload[2:]
		}
		if hasCS {
			lines = append(lines, fmt.Sprintf("CS=0x%02X", cs))
		}
		lines = append(lines, decodeCmdData(cmd, params, false)...)
	}
	return lines
}

func decodeDataLine(dataStr string, isRcv bool) []string {
	raw := extractHexBytes(dataStr)
	if len(raw) == 0 {
		collapsed := reNUL.ReplaceAllStringFunc(dataStr, func(m string) string {
			n := strings.Count(m, "[NUL]")
			return fmt.Sprintf("[NUL×%d]", n)
		})
		s := strings.TrimSpace(collapsed)
		s = safeTruncate(s, 150)
		return []string{"Data: " + s}
	}

	prefix, body := prefixInfo(raw)
	var out []string
	if len(prefix) > 0 {
		out = append(out, "перед кадром: "+strings.Join(prefix, ", "))
	}

	pkt := findPacket(body)
	if pkt != nil {
		isResp := isRcv || len(prefix) > 0
		out = append(out, parsePayload(pkt.payload, isResp)...)
		rest := body[pkt.end:]
		nonzero := false
		for _, b := range rest {
			if b != 0 {
				nonzero = true
				break
			}
		}
		if nonzero {
			if len(rest) == 2 {
				out = append(out, fmt.Sprintf("CRC16=0x%02X%02X", rest[0], rest[1]))
			} else {
				out = append(out, fmt.Sprintf("+хвост % x", rest))
			}
		}
	} else {
		txt := cp866Decode(body)
		if txt != "" {
			txt = safeTruncate(txt, 120)
			out = append(out, "Data: "+txt)
		} else {
			n := 40
			if n > len(body) {
				n = len(body)
			}
			out = append(out, fmt.Sprintf("Raw: % x...", body[:n]))
		}
	}
	return out
}

// decodeLineToUTF8 converts a raw log line (often Windows-1251) to valid UTF-8.
func decodeLineToUTF8(raw []byte) string {
	// already valid UTF-8?
	if utf8.Valid(raw) {
		return string(raw)
	}
	// try Windows-1251 (typical for ICSFP logs with [ЕП-12])
	var sb strings.Builder
	sb.Grow(len(raw))
	for _, c := range raw {
		r := cp1251Table[c]
		if r == 0 && c >= 0x80 {
			r = rune(c)
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// safeTruncate cuts s to at most n runes without splitting UTF-8 sequences.
func safeTruncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// ========================= Обработка файла =========================

func processFile(filepathIn, outputPath string) error {
	fmt.Printf("Обработка: %s\n  → %s\n", filepathIn, outputPath)
	f, err := os.Open(filepathIn)
	if err != nil {
		return err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	// large lines in logs
	buf := make([]byte, 0, 1024*1024)
	sc.Buffer(buf, 4*1024*1024)
	for sc.Scan() {
		lines = append(lines, decodeLineToUTF8(sc.Bytes()))
	}
	if err := sc.Err(); err != nil {
		return err
	}

	var newLines []string
	stats := struct {
		snd, rcv int
		cmds     map[int]int
	}{cmds: map[int]int{}}

	for _, rawLine := range lines {
		// Только расшифровка, исходный hex не пишем
		if strings.Contains(rawLine, "WAITING") {
			ts := ""
			if len(rawLine) >= 21 {
				ts = strings.TrimRight(rawLine[:21], " ") + "  "
			}
			newLines = append(newLines, ts+"| ожидание ответа (ЭККР может слать SYN)\n")
			continue
		}

		if !strings.Contains(rawLine, "Data:") {
			continue
		}

		isRcv := strings.Contains(rawLine, "Rcv") || strings.Contains(strings.ToLower(rawLine), "receive data")
		isSnd := strings.Contains(rawLine, "Snd")

		ts := ""
		if len(rawLine) >= 21 {
			ts = strings.TrimRight(rawLine[:21], " ") + "  "
		}
		dir := "-->"
		if isRcv {
			dir = "<--"
		}

		m := reData.FindStringSubmatch(rawLine)
		if m == nil {
			continue
		}
		dataContent := m[1]
		var decoded []string
		func() {
			defer func() {
				if r := recover(); r != nil {
					decoded = []string{fmt.Sprintf("[ошибка: %v]", r)}
				}
			}()
			decoded = decodeDataLine(dataContent, isRcv)
		}()
		if len(decoded) == 0 {
			continue
		}

		pad := strings.Repeat(" ", len([]rune(ts)))
		newLines = append(newLines, fmt.Sprintf("%s%s %s\n", ts, dir, decoded[0]))
		for _, d := range decoded[1:] {
			newLines = append(newLines, fmt.Sprintf("%s   %s\n", pad, d))
		}
		newLines = append(newLines, "\n")

		if isSnd {
			stats.snd++
		}
		if isRcv {
			stats.rcv++
		}
		if fm := reFuncID.FindStringSubmatch(rawLine); fm != nil {
			c, _ := strconv.Atoi(fm[1])
			stats.cmds[c]++
		}
	}

	var header []string
	header = append(header,
		"РАСШИФРОВКА ЛОГА ОБМЕНА ПК <-> ЭККР ІКС-Е810Т\n",
		strings.Repeat("=", 80)+"\n",
		fmt.Sprintf("Исходный файл : %s\n", filepath.Base(filepathIn)),
		fmt.Sprintf("Строк исходных: %d\n", len(lines)),
		fmt.Sprintf("Snd: %d  Rcv: %d\n", stats.snd, stats.rcv),
		"Команды (по func ID):\n",
	)
	var codes []int
	for c := range stats.cmds {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	for _, c := range codes {
		name := cmdNames[c]
		header = append(header, fmt.Sprintf("  Код %3d  %5d   %s\n", c, stats.cmds[c], name))
	}
	header = append(header,
		strings.Repeat("=", 80)+"\n",
		"Только расшифровка (исходный hex не сохраняется).\n",
		strings.Repeat("=", 80)+"\n\n",
	)

	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()
	w := bufio.NewWriter(out)
	for _, h := range header {
		w.WriteString(h)
	}
	for _, l := range newLines {
		w.WriteString(l)
	}
	w.Flush()
	fmt.Printf("  OK, строк выхода: %d\n", len(header)+len(newLines))
	return nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func main() {
	files := os.Args[1:]
	if len(files) == 0 {
		matches, _ := filepath.Glob("*.log")
		matches2, _ := filepath.Glob("log/*.log")
		files = append(matches, matches2...)
		filtered := files[:0]
		for _, f := range files {
			base := strings.ToLower(filepath.Base(f))
			if !strings.Contains(base, "_decoded") {
				filtered = append(filtered, f)
			}
		}
		files = filtered
	}

	if len(files) == 0 {
		fmt.Println("Укажите .log файл: go run . file.log")
		return
	}

	outDir := "Decod_log"
	os.MkdirAll(outDir, 0o755)

	for _, f := range files {
		if fi, err := os.Stat(f); err != nil || fi.IsDir() {
			fmt.Printf("Нет файла: %s\n", f)
			continue
		}
		base := filepath.Base(f)
		ext := filepath.Ext(base)
		name := strings.TrimSuffix(base, ext)
		out := filepath.Join(outDir, name+"_decoded_v2"+ext)
		if err := processFile(f, out); err != nil {
			fmt.Printf("Ошибка %s: %v\n", f, err)
		}
	}
	fmt.Println("Готово.")
}
