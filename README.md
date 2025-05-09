# RecogApp - Security Scanner

#### por Pedro Dutra

O RecogApp é uma ferramenta de análise de segurança com interface gráfica que reúne diversas funcionalidades para reconhecimento e avaliação de segurança de domínios e sistemas.

## Funcionalidades

- **Port Scanning**: Identifica portas abertas em servidores e dispositivos de rede
- **Subdomain Discovery**: Detecta subdomínios associados a um domínio principal
- **WHOIS Lookup**: Obtém informações de registro de domínios e endereços IP
- **DNS Enumeration**: Realiza consultas DNS para obter informações sobre domínios
- **Vulnerability Scanning**: Identifica possíveis vulnerabilidades em sistemas e serviços

## Requisitos

- Python 3.6+
- PyQt5
- dnspython
- Nmap (para a funcionalidade de Vulnerability Scanning)
- No Windows: WSL (Windows Subsystem for Linux) para executar algumas ferramentas baseadas em Linux

## Instalação

1. Clone o repositório:

```bash
git clone https://github.com/seu-usuario/recogapp.git
cd recogapp
```

2. Instale as dependências:

```bash
pip install -r requirements.txt
```

3. Configuração adicional (Windows):

   - Instale o [WSL (Windows Subsystem for Linux)](https://docs.microsoft.com/pt-br/windows/wsl/install)
   - Dentro do WSL, instale o Nmap:

   ```bash
   sudo apt update
   sudo apt install nmap whois
   ```

4. Configuração adicional (Linux/macOS):

   - Instale o Nmap e o Whois:

   ```bash
   # Debian/Ubuntu
   sudo apt update
   sudo apt install nmap whois
   
   # Fedora
   sudo dnf install nmap whois
   
   # macOS
   brew install nmap whois
   ```

## Uso

Execute a aplicação:

```bash
python main.py
```

### Port Scan

1. Na aba "PortScan", insira o domínio ou IP alvo
2. Defina o intervalo de portas a serem verificadas ou use um dos presets
3. Ajuste o número de threads
4. Clique em "Iniciar Scan"

### Subdomain Scanner

1. Na aba "Subdomains", insira o domínio alvo
2. Selecione o modo de scan:
   - Rápido: Verifica os subdomínios mais comuns
   - Moderado: Equilíbrio entre velocidade e cobertura
   - Completo: Verifica uma lista extensa de subdomínios
   - Personalizado: Utilize uma lista própria de subdomínios
3. Clique em "Iniciar Scan"

### WHOIS Lookup

1. Na aba "WHOIS", insira o domínio ou IP alvo
2. Clique em "Iniciar WHOIS"

### DNS Enumeration

1. Na aba "DNS", insira o domínio alvo
2. Clique em "Iniciar DNS"

### Vulnerability Scanning

1. Na aba "VulnScan", insira o domínio ou IP alvo
2. Selecione a intensidade:
   - Leve: Scan básico e discreto
   - Normal: Equilíbrio entre detecção e discrição
   - Agressivo: Verificação mais completa (pode ser detectado por sistemas de segurança)
3. Clique em "Iniciar VulnScan"

## Salvando Resultados

Cada funcionalidade possui um botão "Salvar Resultados" que permite exportar os dados obtidos para um arquivo de texto.

## Considerações de Segurança

- **Importante**: Use esta ferramenta apenas em sistemas que você tem permissão para analisar
- O uso inadequado para escanear sistemas sem autorização pode ser ilegal
- Algumas funcionalidades podem ser detectadas por sistemas de segurança como tentativas de intrusão
