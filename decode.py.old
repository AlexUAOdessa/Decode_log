import glob
import os
import re

def smart_decode_data_with_block_size(match):
    data_content = match.group(1)
    tokens = data_content.strip().split()
    
    total_bytes = len(tokens)
    
    # Обрезаем хвостики из пустых нулей/паддинга для чистоты текста
    last_meaningful_idx = total_bytes - 1
    while last_meaningful_idx >= 0:
        t = tokens[last_meaningful_idx]
        if t.lower() in ["0x00", "0x0ff", "0xff"]:
            last_meaningful_idx -= 1
        else:
            break
            
    filled_bytes = max(0, last_meaningful_idx + 1)
    meaningful_tokens = tokens[:filled_bytes] if filled_bytes > 0 else tokens
    
    decoded = []
    for t in meaningful_tokens:
        if t.startswith("0x") or t.startswith("0X"):
            try:
                val = int(t, 16)
                if val == 0x20:
                    decoded.append(" ")
                elif 32 <= val <= 126:
                    decoded.append(chr(val))
                elif val > 127:
                    c = bytes([val]).decode('cp866')
                    if c.isprintable():
                        decoded.append(c)
                    else:
                        decoded.append(t)
                else:
                    decoded.append(t)
            except:
                decoded.append(t)
        else:
            decoded.append(t)
            
    # Сборка текста
    output = []
    current_word = []
    
    for item in decoded:
        if item == " ":
            if current_word:
                output.append("".join(current_word))
                current_word = []
            output.append(" ")
        elif item.startswith("0x") or item.startswith("0X"):
            if current_word:
                output.append("".join(current_word))
                current_word = []
            output.append(f" {item} ")
        else:
            if len(item) == 1:
                current_word.append(item)
            else:
                if current_word:
                    output.append("".join(current_word))
                    current_word = []
                output.append(f" {item} ")
                
    if current_word:
        output.append("".join(current_word))
        
    result_str = "".join(output)
    result_str = re.sub(r'\s+', ' ', result_str).strip()
    
    # Выводим только размер блока
    stats_info = f"[Размер блока: {total_bytes}б]"
    
    return f"Data: {result_str}  {stats_info}"

def process_logs():
    input_dir = "log"
    output_dir = "decode_log"
    
    os.makedirs(input_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
    
    search_path = os.path.join(input_dir, "*.log")
    log_files = glob.glob(search_path)
    
    if not log_files:
        print(f"В папке '{input_dir}' не найдено файлов с расширением .log.")
        return

    print(f"Найдено лог-файлов для обработки: {len(log_files)}")

    for filepath in log_files:
        filename = os.path.basename(filepath)
        print(f"Обработка файла: {filename}...")
        
        base_name, ext = os.path.splitext(filename)
        output_filepath = os.path.join(output_dir, f"{base_name}_decoded{ext}")

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            new_lines = []
            for line in lines:
                if "Data:" in line:
                    processed_line = re.sub(
                        r'Data:\s*(0x[0-9A-Fa-f]{2}(\s+0x[0-9A-Fa-f]{2})*)', 
                        smart_decode_data_with_block_size, 
                        line
                    )
                    new_lines.append(processed_line)
                else:
                    new_lines.append(line)

            with open(output_filepath, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
                
            print(f" -> Успешно сохранено в: {output_filepath}")
            
        except Exception as e:
            print(f"Ошибка при обработке файла {filename}: {e}")

if __name__ == "__main__":
    process_logs()