from .utils import (
    validate_target, is_tool_available, fast_port_scan,
    run_cmd_with_cancel, register_scan, is_scan_cancelled,
    cleanup_scan, cancel_scan
)

def run(target: str, scan_intensity: str = "normal"):
    thread_id = register_scan("vulnerability")

    try:
        if not target:
            yield "Erro: Alvo não especificado."
            return

        if not validate_target(target):
            yield f"Erro: '{target}' não parece ser um domínio válido."
            yield "O formato do alvo deve ser IP ou 'example.com' sem 'http://' ou 'https://'."
            return

        if not is_tool_available("nmap"):
            yield "Erro: Nmap não está instalado ou acessível."
            return

        if is_scan_cancelled(thread_id):
            yield "[!] Scan cancelado pelo usuário antes de iniciar."
            return

        yield f"Iniciando escaneamento de vulnerabilidades em {target} (modo: {scan_intensity})\n"
        yield "Etapa 1: Identificando portas abertas...\n"

        port_range = (1, 1024) if scan_intensity != "aggressive" else (1, 65535)
        open_ports = fast_port_scan(target, port_range[0], port_range[1], threads=200,
                                    is_cancelled=lambda: is_scan_cancelled(thread_id))

        if is_scan_cancelled(thread_id):
            yield "[!] Scan cancelado pelo usuário durante a varredura de portas."
            return

        if not open_ports:
            yield "Nenhuma porta aberta encontrada."
            return

        ports_str = ",".join(open_ports)
        yield f"Portas abertas detectadas: {ports_str}\n"

        yield "Etapa 2: Escaneando vulnerabilidades nas portas abertas...\n"

        scan_options = {
            "light": ["-p", ports_str, "-sV", "--script", "default,safe", "-T3"],
            "normal": ["-p", ports_str, "-sV", "--script", "default,vuln", "-T4"],
            "aggressive": ["-p", ports_str, "-sV", "--script", "default,vuln,exploit", "-A", "-T4"]
        }

        options = scan_options.get(scan_intensity, scan_options["normal"])
        timeout = 600 if scan_intensity == "aggressive" else 300
        cmd = ["nmap", "-Pn"] + options + [target]

        yield f"Executando: {' '.join(cmd)}\n(Aguarde...)\n"

        if is_scan_cancelled(thread_id):
            yield "[!] Scan cancelado pelo usuário antes de iniciar o scan de vulnerabilidades."
            return

        scan = run_cmd_with_cancel(cmd, timeout=timeout,
                                   is_cancelled=lambda: is_scan_cancelled(thread_id))

        if is_scan_cancelled(thread_id):
            yield "[!] Scan cancelado pelo usuário durante o scan de vulnerabilidades."
            return

        if scan.returncode == 0 and scan.stdout:
            for line in scan.stdout.splitlines():
                if is_scan_cancelled(thread_id):
                    yield "[!] Processamento de resultados interrompido."
                    return
                yield line
            yield "\n⚠️ Atenção: Serviços marcados como 'tcpwrapped' ou 'filtered' podem estar protegidos por firewall ou IDS."
        else:
            yield f"Falha no scan de vulnerabilidades: {scan.stderr or 'erro desconhecido.'}"

    finally:
        cleanup_scan(thread_id)

def cancel_current_scan():
    return cancel_scan()

run.cancel_current_scan = cancel_current_scan
