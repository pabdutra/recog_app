import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import validate_target, scan_port, register_scan, is_scan_cancelled, cleanup_scan, cancel_scan

def run(target: str, port_range: str = "1-1024", threads: int = 10):
    # Registra o scan
    thread_id = register_scan("port")
    
    try:
        if not target:
            yield "Erro: Alvo não especificado."
            return

        if not validate_target(target):
            yield f"Erro: '{target}' não parece ser um domínio válido."
            yield "O formato do alvo deve ser IP ou 'example.com' sem 'http://' ou 'https://'."
            return

        try:
            parts = port_range.split('-')
            start, end = (int(parts[0]), int(parts[0])) if len(parts) == 1 else map(int, parts)
            if start < 1 or end > 65535 or start > end:
                yield "Erro: Intervalo de portas inválido. Use números entre 1-65535."
                return
        except ValueError:
            yield "Erro: Intervalo inválido. Use o formato start-end (ex: 1-1024)."
            return

        port_count = end - start + 1
        effective_threads = min(threads, port_count)

        yield f"Iniciando scan em {target} nas portas {start}-{end} com {effective_threads} threads...\n"

        open_ports = []
        try:
            with ThreadPoolExecutor(max_workers=effective_threads) as executor:
                # Criamos um dicionário de futures para permitir cancelamento seletivo
                futures = {executor.submit(scan_port, target, p, timeout=1.5): p for p in range(start, end + 1)}
                
                # Lista para rastrear futures pendentes
                pending_futures = list(futures.keys())
                
                for future in as_completed(futures):
                    # Verifica o cancelamento frequentemente
                    if is_scan_cancelled():
                        # Cancela todas as futures pendentes imediatamente
                        for f in pending_futures:
                            if not f.done():
                                f.cancel()
                        yield "\n[!] Scan cancelado pelo usuário."
                        return
                    
                    # Remove esta future da lista de pendentes
                    if future in pending_futures:
                        pending_futures.remove(future)
                        
                    port, is_open = future.result()
                    if is_open:
                        open_ports.append(port)
                        try:
                            service_name = socket.getservbyport(port)
                        except:
                            service_name = "desconhecido"
                        yield f"{port}/tcp - {service_name}"
        except Exception as e:
            yield f"Erro durante o scan: {str(e)}"
            return

        if not is_scan_cancelled():
            if not open_ports:
                yield f"\nNenhuma porta aberta encontrada em {target} no intervalo {start}-{end}."
            else:
                yield f"\nTotal de portas abertas encontradas: {len(open_ports)}"
    finally:
        cleanup_scan()

def cancel_current_scan():
    return cancel_scan()

run.cancel_current_scan = cancel_current_scan