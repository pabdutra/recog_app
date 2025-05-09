from .utils import (
    validate_target, run_cmd_with_cancel,
    register_scan, is_scan_cancelled, cleanup_scan, cancel_scan
)

def run(target: str):
    # Registra o scan
    thread_id = register_scan("whois")
    
    try:
        if not target:
            yield "Erro: Alvo não especificado."
            return

        if not validate_target(target):
            yield f"Erro: '{target}' não parece ser um domínio válido."
            yield "O formato do deve ser IP ou 'example.com' sem 'http://' ou 'https://'."
            return

        yield f"Consultando WHOIS para {target}...\n"
        res = run_cmd_with_cancel(["whois", target], timeout=30)

        if res.returncode == 0 and res.stdout:
            output = res.stdout.strip()
            if "No match" in output or "Not found" in output:
                yield f"Nenhuma informação WHOIS encontrada para {target}."
            else:
                for line in output.splitlines():
                    if is_scan_cancelled():
                        yield "\n[!] Processamento de resultados interrompido."
                        return
                    yield line
        else:
            if "processo encerrado" in (res.stderr or "").lower() or "killed" in (res.stderr or "").lower():
                yield "[!] Consulta WHOIS cancelada pelo usuário."
            else:
                yield f"Erro WHOIS: {res.stderr or 'Erro desconhecido.'}"
    finally:
        cleanup_scan()

def cancel_current_scan():
    return cancel_scan()

run.cancel_current_scan = cancel_current_scan