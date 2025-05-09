import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QLineEdit, QPushButton, QTextEdit, QSpinBox, QFileDialog, 
    QMessageBox, QComboBox, QRadioButton, QButtonGroup, QCheckBox, QGroupBox
)
from PyQt5.QtCore import QRunnable, QThreadPool, pyqtSignal, QObject, Qt

import modules.portscan as portscan
import modules.whois_lookup as whois_lookup
import modules.dns_enumeration as dns_enum
import modules.subdomain_scanner as subdomain_scanner
import modules.vuln_scan as vuln_scan
import threading

class WorkerSignals(QObject):
    result = pyqtSignal(str)
    progress = pyqtSignal(str)
    finished = pyqtSignal()

class Worker(QRunnable):
    def __init__(self, fn, *args):
        super().__init__()
        self.fn = fn
        self.args = args
        self.signals = WorkerSignals()
        self.is_cancelled = False
        self.running = False
        self.thread_id = None
    
    def run(self):
        self.running = True
        self.thread_id = threading.get_ident()
        try:
            if hasattr(self.fn, '__next__'):  # É um gerador
                result = self.fn
            else:
                result = self.fn(*self.args)
                
            if hasattr(result, '__iter__') and not isinstance(result, str):
                for line in result:
                    if self.is_cancelled:
                        self.signals.progress.emit("\n[!] Scan interrompido pelo usuário.")
                        break
                    self.signals.progress.emit(str(line))
                if not self.is_cancelled:
                    self.signals.result.emit("Scan finalizado.")
            else:
                self.signals.result.emit(str(result))
        except Exception as e:
            self.signals.result.emit(f"Erro na execução: {str(e)}")
        finally:
            self.running = False
            self.signals.finished.emit()
    
    def cancel(self):
        self.is_cancelled = True


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RecogApp - Security Scanner")
        self.resize(900, 650)
        self.pool = QThreadPool()
        self.current_workers = {}
        
        tabs = QTabWidget()
        tabs.addTab(self.init_portscan_tab(), "PortScan")
        tabs.addTab(self.init_subdomain_tab(), "Subdomains")
        
        for tab_name, config in {
            "WHOIS": (whois_lookup.run, "Domínio"),
            "DNS": (dns_enum.run, "Domínio"),
            "VulnScan": (self.run_vuln_scan, "Alvo")
        }.items():
            tabs.addTab(self.init_generic_tab(tab_name, *config), tab_name)
        
        tabs.addTab(self.init_help_tab(), "Ajuda")
        
        self.setCentralWidget(tabs)

    def init_portscan_tab(self):
        w = QWidget()
        l = QVBoxLayout(w)
        
        input_group = QGroupBox("Configuração do Scan")
        form = QVBoxLayout(input_group)
        
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Alvo:"))
        tgt = QLineEdit()
        target_layout.addWidget(tgt)
        form.addLayout(target_layout)
        
        scan_options = QHBoxLayout()
        scan_options.addWidget(QLabel("Portas:"))
        pr = QLineEdit("1-1024")
        scan_options.addWidget(pr)
        
        scan_options.addWidget(QLabel("Threads:"))
        th = QSpinBox()
        th.setRange(1, 200)
        th.setValue(20)
        scan_options.addWidget(th)
        
        scan_options.addStretch()
        form.addLayout(scan_options)
        
        preset_layout = QHBoxLayout()
        preset_layout.addWidget(QLabel("Presets:"))
        
        preset_buttons = []
        for name, value in [
            ("Padrão", "1-1024"), 
            ("Completo", "1-65535"),
            ("Comuns", "21,22,23,25,53,80,110,139,143,443,445,587,993,995,1433,3306,3389,5900,8080")
        ]:
            btn = QPushButton(name)
            btn.clicked.connect(lambda checked, val=value: pr.setText(val))
            preset_layout.addWidget(btn)
            preset_buttons.append(btn)
            
        form.addLayout(preset_layout)
        
        btn_layout = QHBoxLayout()
        start_btn = QPushButton("Iniciar Scan")
        btn_layout.addWidget(start_btn)
        
        cancel_btn = QPushButton("Cancelar")
        cancel_btn.setEnabled(False)
        btn_layout.addWidget(cancel_btn)
        
        save = QPushButton("Salvar Resultados")
        btn_layout.addWidget(save)
        form.addLayout(btn_layout)
        
        l.addWidget(input_group)
        
        results_group = QGroupBox("Resultados")
        results_layout = QVBoxLayout(results_group)
        
        out = QTextEdit()
        out.setReadOnly(True)
        results_layout.addWidget(out)
        
        l.addWidget(results_group, 1)
        
        def go():
            if not tgt.text():
                QMessageBox.warning(w, "Aviso", "Por favor, informe um alvo para o scan.")
                return
                
            start_btn.setEnabled(False)
            cancel_btn.setEnabled(True)
            out.clear()
            out.append(f"Iniciando scan de portas em {tgt.text()}...\n")
            
            worker = Worker(portscan.run, tgt.text(), pr.text(), th.value())
            self.current_workers["PortScan"] = worker
            
            out.clear()
            worker.signals.progress.connect(lambda line: out.append(line))
            worker.signals.finished.connect(lambda: self.on_scan_finished("PortScan", start_btn, cancel_btn))
            self.pool.start(worker)
        
        def cancel_scan():
            if "PortScan" in self.current_workers:
                worker = self.current_workers["PortScan"]
                if worker.running:
                    worker.cancel()
                    out.append("\n[!] Cancelando scan... aguarde a finalização das tarefas em execução.")
                    cancel_btn.setEnabled(False)
        
        start_btn.clicked.connect(go)
        cancel_btn.clicked.connect(cancel_scan)
        save.clicked.connect(lambda: self.save_output(out.toPlainText()))
        
        return w

    def init_subdomain_tab(self):
        w = QWidget()
        l = QVBoxLayout(w)
        
        input_group = QGroupBox("Configuração")
        form = QVBoxLayout(input_group)
        
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Domínio:"))
        domain_input = QLineEdit()
        target_layout.addWidget(domain_input)
        form.addLayout(target_layout)
        
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("Modo de scan:"))
        
        scan_modes = QButtonGroup(w)
        modes = [
            ("Rápido", "quick"), 
            ("Moderado", "moderate"),
            ("Completo", "full"),
            ("Personalizado", "custom")
        ]
        
        for i, (label, value) in enumerate(modes):
            radio = QRadioButton(label)
            radio.setProperty("value", value)
            if value == "moderate":
                radio.setChecked(True)
            scan_modes.addButton(radio, i)
            mode_layout.addWidget(radio)
        
        form.addLayout(mode_layout)
        
        custom_file_layout = QHBoxLayout()
        custom_file_layout.addWidget(QLabel("Arquivo de subdomínios:"))
        custom_file_input = QLineEdit()
        custom_file_input.setEnabled(False)
        custom_file_layout.addWidget(custom_file_input)
        
        browse_btn = QPushButton("Procurar")
        browse_btn.setEnabled(False)
        custom_file_layout.addWidget(browse_btn)
        form.addLayout(custom_file_layout)
        
        for btn in [scan_modes.button(i) for i in range(len(modes))]:
            btn.toggled.connect(lambda checked, b=btn: (
                custom_file_input.setEnabled(checked and b.property("value") == "custom"),
                browse_btn.setEnabled(checked and b.property("value") == "custom")
            ))
        
        browse_btn.clicked.connect(lambda: self.browse_file(custom_file_input, "Selecionar arquivo de subdomínios", "Arquivos de texto (*.txt)"))
        
        btn_layout = QHBoxLayout()
        start_btn = QPushButton("Iniciar Scan")
        btn_layout.addWidget(start_btn)
        
        cancel_btn = QPushButton("Cancelar")
        cancel_btn.setEnabled(False)
        btn_layout.addWidget(cancel_btn)
        
        save = QPushButton("Salvar Resultados")
        btn_layout.addWidget(save)
        form.addLayout(btn_layout)
        
        l.addWidget(input_group)
        
        results_group = QGroupBox("Resultados")
        results_layout = QVBoxLayout(results_group)
        
        out = QTextEdit()
        out.setReadOnly(True)
        results_layout.addWidget(out)
        
        l.addWidget(results_group, 1)
        
        def go():
            if not domain_input.text():
                QMessageBox.warning(w, "Aviso", "Por favor, informe um domínio para o scan.")
                return
            
            selected_mode = None
            for i in range(len(modes)):
                btn = scan_modes.button(i)
                if btn.isChecked():
                    selected_mode = btn.property("value")
                    break
            
            custom_file = custom_file_input.text() if selected_mode == "custom" else None
            if selected_mode == "custom" and not custom_file:
                QMessageBox.warning(w, "Aviso", "Por favor, selecione um arquivo de subdomínios.")
                return
            
            start_btn.setEnabled(False)
            cancel_btn.setEnabled(True)
            out.clear()
            out.append(f"Iniciando scan de subdomínios em {domain_input.text()}...\n")
            
            worker = Worker(subdomain_scanner.run, domain_input.text(), selected_mode, custom_file)
            self.current_workers["Subdomains"] = worker
            
            out.clear()
            worker.signals.progress.connect(lambda line: out.append(line))
            worker.signals.finished.connect(lambda: self.on_scan_finished("Subdomains", start_btn, cancel_btn))
            self.pool.start(worker)
            
        def cancel_scan():
            if "Subdomains" in self.current_workers:
                worker = self.current_workers["Subdomains"]
                if worker.running:
                    worker.cancel()
                    out.append("\n[!] Cancelando scan... aguarde a finalização das tarefas em execução.")
                    cancel_btn.setEnabled(False)
        
        start_btn.clicked.connect(go)
        cancel_btn.clicked.connect(cancel_scan)
        save.clicked.connect(lambda: self.save_output(out.toPlainText()))
        
        return w

    def init_generic_tab(self, name, func, target_label="Alvo"):
        w = QWidget()
        l = QVBoxLayout(w)
        
        input_group = QGroupBox("Configuração")
        form = QVBoxLayout(input_group)
        
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel(f"{target_label}:"))
        target_input = QLineEdit()
        target_layout.addWidget(target_input)
        form.addLayout(target_layout)
        
        specific_controls = {}
        
        if name == "VulnScan":
            intensity_layout = QHBoxLayout()
            intensity_layout.addWidget(QLabel("Intensidade:"))
            
            intensity_combo = QComboBox()
            for label, value in [
                ("Leve", "light"),
                ("Normal", "normal"),
                ("Agressivo", "aggressive")
            ]:
                intensity_combo.addItem(label, value)
            
            intensity_layout.addWidget(intensity_combo)
            intensity_layout.addStretch()
            form.addLayout(intensity_layout)
            
            specific_controls["intensity"] = intensity_combo
        
        btn_layout = QHBoxLayout()
        start_btn = QPushButton(f"Iniciar {name}")
        btn_layout.addWidget(start_btn)
        
        cancel_btn = QPushButton("Cancelar")
        cancel_btn.setEnabled(False)
        btn_layout.addWidget(cancel_btn)
        
        save = QPushButton("Salvar Resultados")
        btn_layout.addWidget(save)
        form.addLayout(btn_layout)
        
        l.addWidget(input_group)
        
        results_group = QGroupBox("Resultados")
        results_layout = QVBoxLayout(results_group)
        
        out = QTextEdit()
        out.setReadOnly(True)
        results_layout.addWidget(out)
        
        l.addWidget(results_group, 1)
        
        def go():
            if not target_input.text():
                QMessageBox.warning(w, "Aviso", f"Por favor, informe um {target_label.lower()} válido.")
                return
            
            start_btn.setEnabled(False)
            cancel_btn.setEnabled(True)
            out.clear()
            out.append(f"Iniciando {name} em {target_input.text()}...\n")
            
            args = [target_input.text()]
            
            if name == "VulnScan":
                intensity = specific_controls["intensity"].currentData()
                args.append(intensity)
            
            out.clear()
            worker = Worker(func, *args)
            self.current_workers[name] = worker
            
            worker.signals.progress.connect(lambda line: out.append(line))
            worker.signals.finished.connect(lambda: self.on_scan_finished(name, start_btn, cancel_btn))
            self.pool.start(worker)
        
        def cancel_scan():
            if name in self.current_workers:
                worker = self.current_workers[name]
                if worker.running:
                    worker.cancel()
                    out.append("\n[!] Cancelando scan... aguarde a finalização das tarefas em execução.")
                    cancel_btn.setEnabled(False)
        
        start_btn.clicked.connect(go)
        cancel_btn.clicked.connect(cancel_scan)
        save.clicked.connect(lambda: self.save_output(out.toPlainText()))
        
        return w
    
    def on_scan_finished(self, tab_name, start_btn, cancel_btn):
        if tab_name in self.current_workers:
            self.current_workers.pop(tab_name)
        start_btn.setEnabled(True)
        cancel_btn.setEnabled(False)
    
    def init_help_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        
        help_text = QTextEdit()
        help_text.setReadOnly(True)
        
        help_content = """
# Funcionalidades do RecogApp - Security Scanner

## PortScan
Identifica portas abertas em um servidor ou dispositivo de rede.
- **Alvo**: Domínio ou endereço IP a ser analisado
- **Portas**: Intervalo de portas (ex: 1-1024) ou portas específicas (ex: 80,443,8080)
- **Threads**: Número de conexões simultâneas (maior = mais rápido, porém mais agressivo)
- **Presets**: Configurações predefinidas para facilitar o uso

## Subdomains
Descobre subdomínios associados a um domínio principal.
- **Domínio**: Nome de domínio a ser analisado (ex: example.com)
- **Modos de Scan**:
  - Rápido: Verifica apenas os subdomínios mais comuns
  - Moderado: Equilíbrio entre velocidade e cobertura
  - Completo: Verifica uma lista extensa de subdomínios
  - Personalizado: Utiliza uma lista de subdomínios fornecida pelo usuário

## WHOIS
Obtém informações de registro de domínios e endereços IP.
- Exibe dados como registrador, datas de criação/expiração e informações de contato

## DNS
Realiza consultas DNS para obter informações sobre um domínio.
- Verifica diversos tipos de registros (A, AAAA, MX, TXT, NS, SOA, CNAME)

## VulnScan
Identifica possíveis vulnerabilidades em sistemas e serviços.
- **Intensidade**:
  - Leve: Scan básico e discreto
  - Normal: Equilíbrio entre detecção e discrição
  - Agressivo: Verificação mais completa (pode ser detectado por sistemas de segurança)
- Requer que o Nmap esteja instalado no sistema
- No Windows, requer WSL (Windows Subsystem for Linux)

## Dicas Gerais
- Os resultados de todos os scans podem ser salvos em arquivos de texto
- Execute scans apenas em sistemas que você tem permissão para analisar
- Algumas funcionalidades podem requerer privilégios de administrador
- Use o botão 'Cancelar' para interromper um scan em andamento
"""
        
        help_text.setMarkdown(help_content)
        layout.addWidget(help_text)
        
        return w
    
    def run_vuln_scan(self, target, intensity="normal"):
        return vuln_scan.run(target, intensity)
    
    def browse_file(self, line_edit, title="Selecionar arquivo", file_filter="All Files (*)"):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, title, "", file_filter, options=options)
        if file_path:
            line_edit.setText(file_path)
    
    def save_output(self, content):
        if not content:
            QMessageBox.warning(self, "Aviso", "Não há conteúdo para salvar.")
            return
            
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(
            self, 
            "Salvar Resultados", 
            "", 
            "Arquivos de texto (*.txt);;Todos os arquivos (*)",
            options=options
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                QMessageBox.information(self, "Sucesso", f"Resultados salvos em {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Erro", f"Falha ao salvar o arquivo: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())