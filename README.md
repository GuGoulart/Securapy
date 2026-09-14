# SecuraPy SIEM

Sistema de Informação e Gerenciamento de Eventos de Segurança (SIEM) simplificado desenvolvido para a disciplina **Coding for Security**.

---

## Integrantes

| Nome | Responsabilidade |
|------|-----------------|
| Gustavo | Módulo 5 (enriquecimento.py) + main.py (integração) |
| (Colega A) | Módulo 1 (coletor.py) + arquivos de log |
| (Colega B) | Módulo 2 (regras.py) + Módulo 3 (detector.py) + regras.json |
| (Colega C) | Módulo 4 (servidor_alertas.py + cliente_alertas.py) + Módulo 6 (relatorios.py) |

---

## Descrição do Projeto

O **SecuraPy** é um SIEM simplificado capaz de:

1. Ler e interpretar logs de três fontes distintas (autenticação, firewall e acesso web)
2. Aplicar regras de detecção configuráveis via arquivo JSON
3. Identificar padrões de ataque automaticamente (brute force, port scan, blacklist)
4. Alertar a equipe de segurança em tempo real via rede TCP
5. Enriquecer eventos com geolocalização via API pública (ipinfo.io)
6. Apresentar relatórios e permitir consultas interativas via menu CLI

---

## Estrutura do Projeto

`
securaPy/
├── main.py                 # Ponto de entrada e menu principal
├── coletor.py              # Módulo 1 — Leitura e parsing de logs
├── regras.py               # Módulo 2 — Motor de regras de detecção
├── detector.py             # Módulo 3 — Detecção de anomalias e ataques
├── servidor_alertas.py     # Módulo 4 — Servidor TCP de alertas em tempo real
├── cliente_alertas.py      # Módulo 4 — Cliente TCP que recebe alertas
├── enriquecimento.py       # Módulo 5 — Consulta a APIs de threat intelligence
├── relatorios.py           # Módulo 6 — Dashboard CLI e geração de relatórios
├── logs/                   # Pasta com arquivos de log para teste
│   ├── auth.log
│   ├── firewall.log
│   └── web_access.log
├── config/
│   └── regras.json         # Arquivo de configuração de regras
├── saida/                  # Pasta para relatórios gerados
└── README.md               # Documentação do projeto
`

---

## Dependências

`
requests
`

Instale com:

`ash
pip install requests
`

---

## Como Executar

### 1. Menu principal (SIEM completo)

`ash
python main.py
`

O menu interativo permite:
- **Opção 1:** Carregar e processar todos os logs
- **Opção 2:** Ver resumo geral (eventos por fonte, alertas por severidade)
- **Opção 3:** Filtrar eventos por fonte, tipo e/ou IP
- **Opção 4:** Buscar todos os dados de um IP específico
- **Opção 5:** Ver Top 10 IPs mais ativos
- **Opção 6:** Ver alertas agrupados por severidade
- **Opção 7:** Enriquecer IPs com geolocalização (ipinfo.io)
- **Opção 8:** Exportar relatório completo em JSON
- **Opção 9:** Iniciar servidor de alertas TCP
- **Opção 0:** Sair

### 2. Servidor e cliente de alertas (em terminais separados)

**Terminal 1 — Servidor:**
`ash
python servidor_alertas.py
`

**Terminal 2 — Cliente:**
`ash
python cliente_alertas.py
`

Comandos disponíveis no cliente: /status, /historico, /sair

### 3. Testar módulos isoladamente

`ash
python coletor.py       # Testa leitura dos logs
python regras.py        # Testa motor de regras
python detector.py      # Testa detecção de anomalias
python relatorios.py    # Testa dashboard
python enriquecimento.py  # Testa consulta de IPs
`

---

## Módulos

### Módulo 1 — coletor.py
Lê os arquivos uth.log, irewall.log e web_access.log, parseando cada linha e normalizando em um dicionário padronizado. Usa os.listdir(), open(), split() e tratamento de erros com 	ry/except.

### Módulo 2 — regras.py
Carrega regras do config/regras.json e avalia cada evento contra as regras ativas. Suporta 5 tipos de condições: usuario_privilegiado, porta_critica, path_traversal, xss e 
econhecimento.

### Módulo 3 — detector.py
Analisa o conjunto completo de eventos para identificar padrões: brute force (contagem de FAILs por IP), port scan (portas únicas por IP usando sets) e IPs em blacklist (interseção de sets).

### Módulo 4 — servidor_alertas.py / cliente_alertas.py
Servidor TCP com suporte a múltiplos clientes simultâneos via threading. Faz broadcast de alertas para todos os clientes conectados. Clientes suportam comandos /status, /historico e /sair.

### Módulo 5 — enriquecimento.py
Consulta a API pública https://ipinfo.io/{ip}/json para obter cidade, região, país e organização de IPs suspeitos. Classifica IPs privados (RFC 1918) sem fazer chamadas à API. Usa cache (dicionário) para evitar consultas repetidas.

### Módulo 6 — relatorios.py
Menu interativo, resumo geral, filtros, busca por IP, Top 10 IPs, exportação JSON e exibição de tabelas formatadas no terminal.

---

## Divisão de Tarefas

| Módulo | Responsável | Descrição |
|--------|-------------|-----------|
| main.py | Gustavo | Integração de todos os módulos, menu principal, tratamento de erros de integração |
| enriquecimento.py | Gustavo | Consulta ipinfo.io, cache, classificação IP privado/público |
| coletor.py | Colega A | Leitura e parsing dos 3 formatos de log |
| 
egras.py | Colega B | Motor de regras, carregamento de JSON, classificação de severidade |
| detector.py | Colega B | Detecção de brute force, port scan, blacklist, resumo consolidado |
| servidor_alertas.py | Colega C | Servidor TCP, threading, broadcast |
| cliente_alertas.py | Colega C | Cliente TCP, recepção de alertas, comandos |
| 
elatorios.py | Colega C | Dashboard CLI, exportação JSON, filtros |
