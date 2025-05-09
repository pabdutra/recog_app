import dns.resolver
from .utils import validate_domain, register_scan, is_scan_cancelled, cleanup_scan, cancel_scan

resolver = dns.resolver.Resolver()
resolver.timeout = 3
resolver.lifetime = 5

def run(target: str):
    thread_id = register_scan("dns")
    
    try:
        if not target:
            yield "Erro: Domínio não especificado."
            return

        if not validate_domain(target):
            yield f"Erro: '{target}' não parece ser um domínio válido."
            yield "O formato deve ser IP ou 'example.com' sem 'http://' ou 'https://'."
            return

        yield f"Resultados DNS para {target}:\n"

        record_types = ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME"]

        for record_type in record_types:
            if is_scan_cancelled():
                yield "\n[!] Consulta DNS cancelada pelo usuário."
                return
                
            yield f"\nRegistros {record_type}:"
            try:
                answers = resolver.resolve(target, record_type)
                for rdata in answers:
                    if is_scan_cancelled():
                        yield "\n[!] Consulta DNS cancelada durante processamento."
                        return
                        
                    if record_type == "MX":
                        yield f"  Prioridade: {rdata.preference}, Servidor: {rdata.exchange}"
                    elif record_type == "SOA":
                        yield f"  Servidor primário: {rdata.mname}"
                        yield f"  Email do responsável: {rdata.rname}"
                        yield f"  Número de série: {rdata.serial}"
                    else:
                        yield f"  {rdata}"
            except dns.resolver.NoAnswer:
                yield "  Sem resposta do servidor DNS"
            except dns.resolver.NXDOMAIN:
                yield "  Domínio não existe"
            except dns.resolver.NoNameservers:
                yield "  Nenhum servidor de nomes disponível"
            except Exception as e:
                yield f"  Erro: {str(e)}"
    finally:
        cleanup_scan()

def cancel_current_scan():
    return cancel_scan()

run.cancel_current_scan = cancel_current_scan