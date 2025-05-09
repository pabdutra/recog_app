import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import time
import random
from .utils import validate_domain, register_scan, is_scan_cancelled, cleanup_scan, cancel_scan

resolver = dns.resolver.Resolver()
resolver.timeout = 5
resolver.lifetime = 6
resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9']

SUBDOMAINS = {
    'quick': [
        'www', 'mail', 'ftp', 'smtp', 'ns1', 'ns2', 'mx', 'admin',
        'blog', 'dev', 'api', 'support', 'test', 'portal', 'cloud'
    ],
    'moderate': [
        'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 
        'dns', 'dns1', 'dns2', 'mx', 'mx1', 'mx2', 'vpn', 'remote', 
        'ssh', 'admin', 'intranet', 'test', 'dev', 'staging',
        'portal', 'api', 'cdn', 'cloud', 'images', 'login', 'blog',
        'shop', 'secure', 'mobile', 'm', 'app', 'support', 'help'
    ],
    'full': [
        'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'imap',
        'ns1', 'ns2', 'ns3', 'dns', 'dns1', 'dns2',
        'mx', 'mx1', 'mx2', 'email', 'mail1', 'mail2', 'pop3', 'outlook',
        'dev', 'devel', 'desenvolvimento', 'homolog', 'staging', 'test', 'teste',
        'app', 'apps', 'aplicativo', 'aplicativos', 'web', 'site', 'portal',
        'host', 'hospedagem', 'api', 'api-docs', 'docs', 'blog', 'forum',
        'admin', 'administracao', 'adm', 'administrativo', 'intranet', 'extranet',
        'login', 'acesso', 'sso', 'auth', 'ldap', 'vpn', 'remote', 'remoto',
        'files', 'arquivos', 'assets', 'cdn', 'media', 'img', 'images', 'imagens',
        'video', 'videos', 'cloud', 'nuvem', 'storage', 'armazenamento',
        'shop', 'loja', 'store', 'compras', 'cart', 'carrinho', 'checkout',
        'ecommerce', 'comercial', 'vendas', 'sales', 'marketing', 'campanhas',
        'sistema', 'system', 'interno', 'internal', 'erp', 'crm', 'rh', 'hr',
        'suporte', 'support', 'helpdesk', 'ajuda', 'help', 'atendimento',
        'db', 'database', 'dados', 'mysql', 'postgres', 'oracle', 'sql',
        'prod', 'producao', 'production', 'monitor', 'status', 'health'
    ]
}

def check_subdomain(domain: str, subdomain: str) -> tuple:
    full_domain = f"{subdomain}.{domain}"
    
    try:
        answers = resolver.resolve(full_domain, 'A')
        ips = [str(r) for r in answers]
        return full_domain, True, ips, None
    except dns.resolver.NXDOMAIN:
        return full_domain, False, [], None
    except dns.resolver.NoAnswer:
        try:
            cname_answers = resolver.resolve(full_domain, 'CNAME')
            cname_targets = [str(r) for r in cname_answers]
            return full_domain, True, [f"CNAME → {target}" for target in cname_targets], None
        except Exception:
            pass
        return full_domain, False, [], None
    except dns.exception.Timeout:
        return full_domain, False, [], None
    except Exception:
        return full_domain, False, [], None

def load_custom_subdomains(file_path: str) -> list:
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except Exception as e:
        raise ValueError(f"Erro ao ler arquivo de subdomínios: {str(e)}")

def run(target: str, scan_level: str = 'moderate', custom_file: str = None):
    # Registra o scan
    thread_id = register_scan("subdomain")
    
    try:
        if not target:
            yield "Erro: Domínio não especificado."
            return

        if not validate_domain(target):
            if validate_domain(f"www.{target}"):
                target = target.lstrip("www.")
                yield f"Ajustando formato do domínio para: {target}"
            else:
                yield f"Erro: '{target}' não parece ser um domínio válido."
                yield "O formato deve ser IP ou 'example.com' sem 'http://' ou 'https://'."
                return

        try:
            socket.gethostbyname(target)
        except socket.gaierror:
            yield f"Alerta: O domínio {target} parece não ter registro DNS."
            return

        if scan_level == 'custom' and custom_file:
            try:
                subdomain_list = load_custom_subdomains(custom_file)
                if not subdomain_list:
                    yield "Erro: Arquivo de subdomínios está vazio."
                    return
            except ValueError as e:
                yield str(e)
                return
        else:
            if scan_level not in SUBDOMAINS:
                scan_level = 'moderate'
            subdomain_list = SUBDOMAINS[scan_level]

        yield f"Buscando subdomínios para {target} [Modo: {scan_level}]..."
        
        try:
            test_query = resolver.resolve("google.com", "A")
        except Exception as e:
            yield f"Erro de conexão DNS: {str(e)}"
            return

        found = []
        
        max_workers = min(20, len(subdomain_list))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            random.shuffle(subdomain_list)
            
            futures = {executor.submit(check_subdomain, target, sub): sub for sub in subdomain_list}
            
            total_subdomains = len(subdomain_list)
            completed = 0
            
            yield f"\nVerificando {total_subdomains} possíveis subdomínios...\n"
            
            for future in as_completed(futures):
                if is_scan_cancelled():
                    yield "\n[!] Scan cancelado pelo usuário."
                    return
                    
                completed += 1
                
                full_domain, exists, ips, error = future.result()
                
                if exists:
                    ip_str = ", ".join(ips)
                    found.append((full_domain, ip_str))
                    yield f"Encontrado: {full_domain} ({ip_str})"
                    
                if completed % 10 == 0:
                    time.sleep(0.1)

        if not is_scan_cancelled():
            if found:
                yield f"\nScan concluído: {len(found)} subdomínios encontrados."
            else:
                yield f"\nScan concluído: Nenhum subdomínio encontrado para {target}."
    finally:
        cleanup_scan()

def cancel_current_scan():
    return cancel_scan()

run.cancel_current_scan = cancel_current_scan