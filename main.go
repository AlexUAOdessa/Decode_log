package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/text/encoding/charmap"
)

// ========================= Справочник команд =========================

var CmdNames = map[int]string{
	0:  "SendStatus — прочитать состояние регистратора",
	1:  "OpenShift — открытие смены",
	2:  "CloseShift — закрытие смены",
	9:  "DayReport — X-отчёт (дневной без обнуления)",
	10: "ArtReport — отчёт по артикулам",
	11: "Comment — строка комментария / текст на чек",
	12: "Sale — регистрация продажи (товар/услуга)",
	13: "DayClrReport — Z-отчёт (дневной с обнулением)",
	14: "Payment — оплата (наличные/карта/…)",
	15: "CancelCheck — аннулирование / отмена чека",
	16: "Avans — служебный внос (внесение наличных)",
	17: "PeriodicReport — периодический отчёт из ФП",
	18: "Sale — регистрация продажи (товар/услуга)",
	20: "Payment — оплата (наличные/карта/…)",
	21: "Fiscalization — фискализация ЭККР",
	22: "SetHeadLine — атрибуты налогоплательщика / заголовок",
	23: "Discount — скидка или наценка",
	25: "SetTaxRate — установка налоговых ставок",
	26: "PeriodicReportShort — короткий периодический отчёт",
	27: "DisplayText — текст на индикатор / дисплей",
	28: "GetTime — прочитать дату/время",
	29: "SetTime — установить дату/время",
	31: "PeriodicReport2 — периодический отчёт по номерам",
	33: "GetBox — сумма наличных в денежном ящике",
	34: "ProgArt — программирование описания товара",
	35: "Discount — скидка или наценка",
	42: "GetDayReport — прочитать данные дневного отчёта",
	43: "GetCheckSums — данные текущего чека",
	44: "GetTaxRates — прочитать налоговые ставки",
	45: "LoadBMP — загрузить логотип торговой точки",
	46: "CplCutter — запрет/разрешение обрезчика",
	47: "SetBarCode — штрих-код чека",
	48: "GetPapStat — состояние бумаги в принтере",
	49: "ArtBarCode — штрих-код артикула в чеке",
	52: "Personaliz — персонализация ЭККР",
	53: "ModemPar — параметры/обмен модема (КСЕФ, эквайер)",
	54: "SetIndType — протокол индикатора клиента",
	58: "Cmd58 — (не документирована в EP-08)",
}

var ModemTags = map[int]string{
	1:  "инициировать обмен с эквайером",
	2:  "безусловный обмен с эквайером",
	3:  "получить пакет КСЕФ",
	4:  "состояние модема (структура)",
	5:  "состояние модема (текст)",
	8:  "проверить пакет КСЕФ",
	9:  "получить номер пакета КСЕФ",
	10: "текущая задача модема",
}

var ModemErr = map[int]string{
	0:   "OK",
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

// ========================= Вспомогательные функции =========================

func hexTokensToBytes(tokens []string) []byte {
	var out []byte
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if strings.HasPrefix(strings.ToLower(t), "0x") {
			val, err := strconv.ParseUint(t[2:], 16, 8)
			if err == nil {
				out = append(out, byte(val))
			}
		}
	}
	return out
}

func cp866Decode(b []byte) string {
	decoder := charmap.CodePage866.NewDecoder()
	utf8Bytes, err := decoder.Bytes(b)
	var s string
	if err != nil {
		// Fallback на Latin1 если кодировка не распозналась
		s = string(b)
	} else {
		s = string(utf8Bytes)
	}

	var sb strings.Builder
	for _, c := range s {
		if (c >= 32 && c <= 126) || c == ' ' || c == '\t' || c >= 128 {
			sb.WriteRune(c)
		} else {
			sb.WriteString(fmt.Sprintf("[%02X]", c))
		}
	}
	return sb.String()
}

func leUint(data []byte, signed bool) int64 {
	if len(data) == 0 {
		return 0
	}
	var val int64
	for i, b := range data {
		val |= int64(b) << uint(8*i)
	}
	if signed {
		bitSize := uint(len(data) * 8)
		if val&(1<<(bitSize-1)) != 0 {
			val -= int64(1) << bitSize
		}
	}
	return val
}

func moneyStr(kopecks int64) string {
	sign := ""
	if kopecks < 0 {
		sign = "-"
		kopecks = -kopecks
	}
	return fmt.Sprintf("%s%d.%02d", sign, kopecks/100, kopecks%100)
}

func collapseNulsAndCtrl(text string) string {
	// Схлопывание [NUL]
	reNul := regexp.MustCompile(`(?:\[NUL\]){2,}`)
	text = reNul.ReplaceAllStringFunc(text, func(m string) string {
		n := strings.Count(m, "[NUL]")
		if n > 1 {
			return fmt.Sprintf("[NUL×%d]", n)
		}
		return "[NUL]"
	})

	// Схлопывание [00]
	re00 := regexp.MustCompile(`(?:\[00\]){2,}`)
	text = re00.ReplaceAllStringFunc(text, func(m string) string {
		n := len(m) / 4
		if n > 1 {
			return fmt.Sprintf("[00×%d]", n)
		}
		return "[00]"
	})

	// Удаление хвостовых нулей
	reTailNul := regexp.MustCompile(`(?:\s*\[NUL(?:×\d+)?\])+\s*$`)
	text = reTailNul.ReplaceAllString(text, "")
	reTail00 := regexp.MustCompile(`(?:\s*\[00(?:×\d+)?\])+\s*$`)
	text = reTail00.ReplaceAllString(text, "")

	return strings.TrimSpace(text)
}

func countNonzero(data []byte) int {
	count := 0
	for _, b := range data {
		if b != 0 {
			count++
		}
	}
	return count
}

func smartBytesToText(data []byte, collapse bool) string {
	if len(data) == 0 {
		return ""
	}

	var result []string
	i := 0
	for i < len(data) {
		// Длинные ASCII фрагменты
		if data[i] >= 32 && data[i] <= 126 {
			j := i
			for j < len(data) && data[j] >= 32 && data[j] <= 126 {
				j++
			}
			if j-i >= 6 {
				result = append(result, string(data[i:j]))
				i = j
				continue
			}
		}

		b := data[i]
		switch {
		case b == 0x00:
			result = append(result, "[NUL]")
		case b == 0x20:
			result = append(result, " ")
		case b >= 32 && b <= 126:
			result = append(result, string(rune(b)))
		case b >= 0x80:
			decoder := charmap.CodePage866.NewDecoder()
			decodedChar, err := decoder.Bytes([]byte{b})
			if err == nil && len(decodedChar) == 1 && decodedChar[0] >= 32 {
				result = append(result, string(decodedChar))
			} else {
				result = append(result, fmt.Sprintf("[%02X]", b))
			}
		default:
			ctrlMap := map[byte]string{
				0x02: "STX", 0x03: "ETX", 0x05: "ENQ", 0x06: "ACK",
				0x10: "DLE", 0x11: "DC1", 0x12: "DC2", 0x15: "NAK",
				0x16: "SYN", 0x17: "ETB", 0x1B: "ESC", 0x1C: "FS",
				0x1D: "GS", 0x1E: "RS", 0x1F: "US",
			}
			name, ok := ctrlMap[b]
			if !ok {
				name = fmt.Sprintf("%02X", b)
			}
			result = append(result, "["+name+"]")
		}
		i++
	}

	text := strings.Join(result, "")
	reSpaces := regexp.MustCompile(`[ \t]+`)
	text = strings.TrimSpace(reSpaces.ReplaceAllString(text, " "))
	if collapse {
		text = collapseNulsAndCtrl(text)
	}
	return text
}

// ========================= Разбор пакета =========================

func findPacket(data []byte) (int, int, []byte) {
	i := 0
	for i < len(data)-3 {
		if data[i] == 0x10 && data[i+1] == 0x02 {
			var payload []byte
			j := i + 2
			for j < len(data)-1 {
				if data[j] == 0x10 && data[j+1] == 0x03 {
					return i, j + 2, payload
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
		i++
	}
	return -1, -1, nil
}

func cmdLabel(cmd int) string {
	if name, ok := CmdNames[cmd]; ok {
		return fmt.Sprintf("Cmd=%02X(%d/%s)", cmd, cmd, name)
	}
	return fmt.Sprintf("Cmd=%02X(%d)", cmd, cmd)
}

func decodeModemPar(data []byte, isResponse bool) string {
	if len(data) == 0 {
		return "[нет данных]"
	}

	if isResponse {
		if len(data) >= 3 {
			code := int(data[0])
			n := int(leUint(data[1:3], false))
			var payload []byte
			if n > 0 && 3+n <= len(data) {
				payload = data[3 : 3+n]
			} else if 3 < len(data) {
				payload = data[3:]
			}

			errStr := ModemErr[code]
			if errStr == "" {
				errStr = fmt.Sprintf("код=%d", code)
			}
			var parts []string
			parts = append(parts, fmt.Sprintf("Result=%d(%s)", code, errStr))
			if n > 0 {
				parts = append(parts, fmt.Sprintf("Len=%d", n))
			}
			if len(payload) > 0 {
				txt := smartBytesToText(payload, true)
				if txt != "" {
					parts = append(parts, fmt.Sprintf("Data: %s", txt))
				}
			}
			return strings.Join(parts, " | ")
		}
		return smartBytesToText(data, true)
	}

	if len(data) >= 5 {
		n := int(leUint(data[2:4], false))
		tag := int(data[4])
		tagName := ModemTags[tag]
		if tagName == "" {
			tagName = fmt.Sprintf("tag=%d", tag)
		}
		var rest []byte
		if 5+max(0, n-1) <= len(data) && n > 0 {
			rest = data[5 : 5+n-1]
		} else if 5 < len(data) {
			rest = data[5:]
		}

		var parts []string
		parts = append(parts, fmt.Sprintf("Tag=%d(%s)", tag, tagName))
		if n > 0 {
			parts = append(parts, fmt.Sprintf("ParamLen=%d", n))
		}
		if len(rest) > 0 {
			if tag == 3 && len(rest) >= 6 {
				pkt := leUint(rest[0:4], false)
				blk := leUint(rest[4:6], false)
				parts = append(parts, fmt.Sprintf("PacketNo=%d Block=%d", pkt, blk))
			} else if tag == 9 && len(rest) >= 5 {
				zrep := leUint(rest[0:2], false)
				ctype := rest[2]
				chk := leUint(rest[3:5], false)
				parts = append(parts, fmt.Sprintf("Z=%d CheckType=%d CheckNo=%d", zrep, ctype, chk))
			} else {
				parts = append(parts, smartBytesToText(rest, true))
			}
		}
		return strings.Join(parts, " | ")
	}

	return smartBytesToText(data, true)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func decodeDiscount(data []byte, isResponse bool) string {
	if isResponse {
		if len(data) >= 4 {
			val := leUint(data[0:4], true)
			if val > 1000000000 || val < -1000000000 {
				return smartBytesToText(data, true)
			}
			rest := data[4:]
			s := fmt.Sprintf("Amount=%s", moneyStr(val))
			if len(rest) > 0 {
				if t := smartBytesToText(rest, true); t != "" {
					s += " " + t
				}
			}
			return s
		}
		return smartBytesToText(data, true)
	}

	if len(data) >= 5 {
		status := data[0]
		amount := leUint(data[1:5], true)
		if amount > 1000000000 || amount < -1000000000 {
			return smartBytesToText(data, true)
		}
		rest := data[5:]
		s := fmt.Sprintf("Status=%02X Discount=%s", status, moneyStr(amount))
		if len(rest) > 0 {
			if t := smartBytesToText(rest, true); t != "" {
				s += " " + t
			}
		}
		return s
	}
	return smartBytesToText(data, true)
}

func decodeStatus(data []byte, isResponse bool) string {
	if !isResponse || len(data) < 2 {
		return smartBytesToText(data, true)
	}

	conf := uint16(leUint(data[0:2], false))
	var flags []string
	bitNames := [][2]interface{}{
		{0, "сборы"}, {1, "режим_оплат"}, {2, "ящик_открыт"}, {3, "чек_выплат"},
		{4, "НДС_добавляемый"}, {5, "смена_открыта"}, {6, "чек_открыт"},
		{9, "логотип"}, {10, "запрет_обрезчика"}, {11, "служебный_отчет"},
		{12, "фискализирован"}, {13, "авар_завершение"}, {14, "OnLine"},
	}
	for _, bn := range bitNames {
		bit := bn[0].(int)
		name := bn[1].(string)
		if conf&(1<<uint(bit)) != 0 {
			flags = append(flags, name)
		}
	}

	var parts []string
	flagStr := "нет"
	if len(flags) > 0 {
		flagStr = strings.Join(flags, ", ")
	}
	parts = append(parts, fmt.Sprintf("Flags=[%s]", flagStr))

	pos := 2
	if pos < len(data) && (data[pos] == 0x11 || data[pos] == 0x12) {
		pos++
	}
	serialEnd := pos + 19
	if serialEnd > len(data) {
		serialEnd = len(data)
	}
	rawSerial := data[pos:serialEnd]
	reCtrl := regexp.MustCompile(`[\x00-\x1f]`)
	serial := strings.TrimSpace(reCtrl.ReplaceAllString(cp866Decode(rawSerial), ""))
	if serial != "" {
		parts = append(parts, fmt.Sprintf("SN='%s'", serial))
	}

	rest := data[serialEnd:]
	if len(rest) > 0 {
		if t := smartBytesToText(rest, true); t != "" {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, " | ")
}

func decodeComment(data []byte, isResponse bool) string {
	if isResponse {
		return smartBytesToText(data, true)
	}
	if len(data) == 0 {
		return "[пусто]"
	}
	n := int(data[0] & 0x7F)
	openPayout := (data[0] & 0x80) != 0
	text := ""
	if n > 0 && 1+n <= len(data) {
		text = cp866Decode(data[1 : 1+n])
	}
	flag := ""
	if openPayout {
		flag = " [открытие чека выплат]"
	}
	return fmt.Sprintf("Len=%d%flag Text='%s'", n, flag, text)
}

func decodeSale(data []byte, isResponse bool) string {
	if isResponse {
		if len(data) >= 8 {
			cost := leUint(data[0:4], true)
			total := leUint(data[4:8], true)
			return fmt.Sprintf("Cost=%s TotalCheck=%s", moneyStr(cost), moneyStr(total))
		}
		return smartBytesToText(data, true)
	}

	if len(data) < 10 {
		return smartBytesToText(data, true)
	}

	qtyRaw := leUint(data[0:3], false)
	status := data[3]
	decimals := int(status & 0x0F)
	printBarcode := (status & 0x40) != 0
	noPrintQty1 := (status & 0x80) != 0
	price := leUint(data[4:8], true)
	tax := data[8]
	taxCh := fmt.Sprintf("%02X", tax)
	if tax >= 0x80 && tax <= 0x85 {
		taxCh = string(rune(tax)) // Приближенная замена для вывода символа ставки
	}
	nameLen := int(data[9])
	name := ""
	if nameLen == 255 {
		name = "[из памяти]"
	} else if nameLen > 0 && 10+nameLen <= len(data) {
		name = cp866Decode(data[10 : 10+nameLen])
	}

	var flags []string
	if printBarcode {
		flags = append(flags, "штрих-код")
	}
	if noPrintQty1 {
		flags = append(flags, "не_печ_кол=1")
	}
	flagStr := ""
	if len(flags) > 0 {
		flagStr = fmt.Sprintf(" [%s]", strings.Join(flags, ", "))
	}

	div := 1.0
	for k := 0; k < decimals; k++ {
		div *= 10.0
	}
	qtyVal := float64(qtyRaw) / div
	qtyFormat := fmt.Sprintf("%%.%df", decimals)

	return fmt.Sprintf("Qty="+qtyFormat+" Price=%s Tax=%s Name='%s'%s",
		qtyVal, moneyStr(price), taxCh, name, flagStr)
}

func decodePayment(data []byte, isResponse bool) string {
	if isResponse {
		if len(data) >= 8 {
			restValSigned := leUint(data[0:4], true)
			packetNo := leUint(data[4:8], false)
			isChange := (restValSigned & 0x80000000) != 0
			restVal := restValSigned & 0x7FFFFFFF
			label := "Остаток"
			if isChange {
				label = "Сдача"
			}
			return fmt.Sprintf("%s=%s PacketNo=%d", label, moneyStr(restVal), packetNo)
		}
		return smartBytesToText(data, true)
	}

	if len(data) < 6 {
		return smartBytesToText(data, true)
	}

	status := data[0]
	payType := status & 0x0F
	nonfiscal := (status & 0x40) != 0
	amountSigned := leUint(data[1:5], true)
	autoClose := (amountSigned & 0x80000000) != 0
	amountVal := amountSigned & 0x7FFFFFFF
	authLen := 0
	if len(data) > 6 {
		authLen = int(data[6])
	}
	auth := ""
	if authLen > 0 && 7+authLen <= len(data) {
		auth = cp866Decode(data[7 : 7+authLen])
	}

	types := map[byte]string{0: "наличные", 1: "карта", 2: "кредит", 3: "чек", 4: "сертификат"}
	tname, ok := types[payType]
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
		flagStr = fmt.Sprintf(" [%s]", strings.Join(flags, ", "))
	}

	return fmt.Sprintf("Type=%s Amount=%s%s Auth='%s'", tname, moneyStr(amountVal), flagStr, auth)
}

func decodeAvans(data []byte, isResponse bool) string {
	if isResponse && len(data) >= 4 {
		return fmt.Sprintf("PacketNo=%d", leUint(data[0:4], false))
	}
	if len(data) >= 4 {
		return fmt.Sprintf("Avans=%s", moneyStr(leUint(data[0:4], true)))
	}
	return smartBytesToText(data, true)
}

func decodeDisplayOrText(data []byte) string {
	if len(data) > 0 && data[0] > 0 && data[0] < 0x40 {
		n := int(data[0])
		if 1+n <= len(data) {
			return fmt.Sprintf("Len=%d Text='%s'", n, cp866Decode(data[1:1+n]))
		}
	}
	return fmt.Sprintf("Text='%s'", cp866Decode(data))
}

func decodeCmdData(cmd int, data []byte, isResponse bool) string {
	if len(data) == 0 {
		return "[нет данных]"
	}

	switch cmd {
	case 0:
		return decodeStatus(data, isResponse)
	case 11:
		return decodeComment(data, isResponse)
	case 12, 18:
		return decodeSale(data, isResponse)
	case 14, 20:
		return decodePayment(data, isResponse)
	case 16:
		return decodeAvans(data, isResponse)
	case 23, 35:
		return decodeDiscount(data, isResponse)
	case 27:
		return decodeDisplayOrText(data)
	case 53:
		return decodeModemPar(data, isResponse)
	default:
		return fmt.Sprintf("Data: %s", smartBytesToText(data, true))
	}
}

func parseCommandPayload(payload []byte, isResponse bool) string {
	if len(payload) < 3 {
		return fmt.Sprintf("[слишком короткий payload: %X]", payload)
	}

	seq := payload[0]
	cmd := int(payload[1])
	var parts []string
	parts = append(parts, fmt.Sprintf("Seq=%02X", seq))
	parts = append(parts, cmdLabel(cmd))

	if isResponse && len(payload) >= 6 {
		status := payload[2]
		result := payload[3]
		reserve := payload[4]
		data := payload[5 : len(payload)-1]
		cs := payload[len(payload)-1]

		parts = append(parts, fmt.Sprintf("Status=%02X", status))
		parts = append(parts, fmt.Sprintf("Result=%02X", result))
		if reserve != 0 {
			parts = append(parts, fmt.Sprintf("Res=%02X", reserve))
		}
		parts = append(parts, fmt.Sprintf("CS=%02X", cs))
		decoded := decodeCmdData(cmd, data, true)
		parts = append(parts, decoded)
	} else {
		params := payload[2 : len(payload)-1]
		cs := payload[len(payload)-1]
		parts = append(parts, fmt.Sprintf("CS=%02X", cs))
		decoded := decodeCmdData(cmd, params, false)
		parts = append(parts, decoded)
	}

	return strings.Join(parts, " | ")
}

// ========================= Обработчик строки =========================

func smartDecodeLine(dataContent string, isRcv bool) string {
	tokens := strings.Fields(dataContent)
	totalBytes := len(tokens)

	last := totalBytes - 1
	for last >= 0 {
		t := strings.ToLower(tokens[last])
		if t == "0x00" || t == "0x0" || t == "0xff" || t == "0x0ff" {
			last--
		} else {
			break
		}
	}
	var meaningful []string
	if last >= 0 {
		meaningful = tokens[:last+1]
	} else {
		meaningful = tokens
	}

	raw := hexTokensToBytes(meaningful)
	if len(raw) == 0 {
		collapsed := collapseNulsAndCtrl(dataContent)
		nulCount := strings.Count(dataContent, "[NUL]")
		nonzeroHint := ""
		if nulCount > 0 {
			nonzeroHint = fmt.Sprintf(", ненулевых≈%d", max(0, totalBytes-nulCount))
		}
		return fmt.Sprintf("Data: %s  [Размер: %dб%s]", collapsed, totalBytes, nonzeroHint)
	}

	var prefix []string
	pos := 0
	for pos < len(raw) {
		if raw[pos] == 0x06 {
			prefix = append(prefix, "ACK")
			pos++
		} else if raw[pos] == 0x16 {
			cnt := 0
			for pos < len(raw) && raw[pos] == 0x16 {
				cnt++
				pos++
			}
			if cnt > 1 {
				prefix = append(prefix, fmt.Sprintf("SYN×%d", cnt))
			} else {
				prefix = append(prefix, "SYN")
			}
		} else if raw[pos] == 0x15 {
			prefix = append(prefix, "NAK")
			pos++
		} else {
			break
		}
	}
	body := raw[pos:]
	nonzero := countNonzero(body)

	start, end, payload := findPacket(body)
	if start != -1 {
		isResp := isRcv || (len(payload) >= 6 && len(prefix) > 0)
		decoded := parseCommandPayload(payload, isResp)
		prefixStr := ""
		if len(prefix) > 0 {
			prefixStr = strings.Join(prefix, " ") + " "
		}
		rest := body[end:]
		restStr := ""
		if len(rest) > 0 {
			restStr = fmt.Sprintf(" +CRC[%X]", rest)
		}
		sizeStr := fmt.Sprintf("[Размер: %dб, ненулевых: %d]", totalBytes, nonzero)
		return fmt.Sprintf("Data: %s%s%s  %s", prefixStr, decoded, restStr, sizeStr)
	}

	prefixStr := ""
	if len(prefix) > 0 {
		prefixStr = strings.Join(prefix, " ") + " "
	}
	text := smartBytesToText(body, true)
	sizeStr := fmt.Sprintf("[Размер: %dб, ненулевых: %d]", totalBytes, nonzero)
	return fmt.Sprintf("Data: %s%s  %s", prefixStr, text, sizeStr)
}

func processFile(filepathIn, filepathOut string) error {
	fmt.Printf("Обработка: %s → %s\n", filepathIn, filepathOut)
	file, err := os.Open(filepathIn)
	if err != nil {
		return err
	}
	defer file.Close()

	var newLines []string
	scanner := bufio.NewScanner(file)
	reData := regexp.MustCompile(`Data:\s*(.*)`)

	for scanner.Scan() {
		line := scanner.Text()
		isRcv := strings.Contains(line, "Rcv") || strings.Contains(strings.ToLower(line), "receive data")

		processed := reData.ReplaceAllStringFunc(line, func(m string) string {
			submatch := reData.FindStringSubmatch(m)
			if len(submatch) > 1 {
				decoded := smartDecodeLine(submatch[1], isRcv)
				return decoded
			}
			return m
		})
		newLines = append(newLines, processed+"\n")
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	outFile, err := os.Create(filepathOut)
	if err != nil {
		return err
	}
	defer outFile.Close()

	writer := bufio.NewWriter(outFile)
	for _, l := range newLines {
		_, _ = writer.WriteString(l)
	}
	writer.Flush()

	fmt.Printf("  OK, строк: %d\n", len(newLines))
	return nil
}

// ========================= Main =========================

func main() {
	execPath, err := os.Executable()
	if err != nil {
		execPath = "."
	}
	scriptDir := filepath.Dir(execPath)

	inputDir := filepath.Join(scriptDir, "log")
	outDir := filepath.Join(scriptDir, "Decod_log")

	if _, err := os.Stat(inputDir); os.IsNotExist(err) {
		cwd, _ := os.Getwd()
		inputDir = filepath.Join(cwd, "log")
	}
	if _, err := os.Stat(outDir); os.IsNotExist(err) {
		outDir = filepath.Join(scriptDir, "Decod_log")
		if _, err := os.Stat(scriptDir); os.IsNotExist(err) {
			cwd, _ := os.Getwd()
			outDir = filepath.Join(cwd, "Decod_log")
		}
	}

	_ = os.MkdirAll(outDir, 0755)

	var files []string
	args := os.Args[1:]
	if len(args) > 0 {
		files = args
	} else {
		if matches, err := filepath.Glob(filepath.Join(inputDir, "*.log")); err == nil {
			files = append(files, matches...)
		}
		if len(files) == 0 {
			if matches, err := filepath.Glob("*.log"); err == nil {
				for _, f := range matches {
					if !strings.Contains(strings.ToLower(f), "_decoded") {
						files = append(files, f)
					}
				}
			}
		}
	}

	var validFiles []string
	for _, f := range files {
		if info, err := os.Stat(f); err == nil && !info.IsDir() {
			if !strings.Contains(strings.ToLower(filepath.Base(f)), "_decoded") {
				validFiles = append(validFiles, f)
			}
		}
	}

	if len(validFiles) == 0 {
		fmt.Println("Лог-файлы не найдены.")
		fmt.Printf("  Ожидаемая папка входа: %s\n", inputDir)
		fmt.Printf("  Или укажите файл: go run main.go file.log\n")
		return
	}

	fmt.Printf("Вход:  %s\n", inputDir)
	fmt.Printf("Выход: %s\n", outDir)
	fmt.Printf("Файлов: %d\n", len(validFiles))

	for _, f := range validFiles {
		base := filepath.Base(f)
		ext := filepath.Ext(base)
		name := strings.TrimSuffix(base, ext)
		outName := fmt.Sprintf("%s_decoded%s", name, ext)
		outPath := filepath.Join(outDir, outName)

		err := processFile(f, outPath)
		if err != nil {
			fmt.Printf("Ошибка %s: %v\n", f, err)
		}
	}

	fmt.Println("Готово.")
}
